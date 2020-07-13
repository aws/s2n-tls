#!/usr/bin/env python3
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not
# use this file except in compliance with the License. A copy of the License is
# located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions
# and limitations under the License.


import argparse
import asyncio
import logging
import math
import os
import pathlib
import subprocess
import sys


DESCRIPTION = "Configure and run all CBMC proofs in parallel"
EPILOG = """
This tool automates the process of running `make report` in each of the CBMC
proof directories. The tool calculates the dependency graph of all tasks needed
to build, run, and report on all the proofs, and executes these tasks in
parallel.
"""


def get_args():
    pars = argparse.ArgumentParser(
        description=DESCRIPTION, epilog=EPILOG)
    for arg in [{
            "flags": ["-j", "--parallel-jobs"],
            "type": int,
            "metavar": "N",
            "help": "run at most N proof jobs in parallel",
    }, {
            "flags": ["--no-standalone"],
            "action": "store_true",
            "help": "only configure proofs: do not initialize nor run",
    }, {
            "flags": ["-p", "--proofs"],
            "nargs": "+",
            "metavar": "P",
            "help": "only run proof P",
    }, {
            "flags": ["--project-name"],
            "metavar": "NAME",
            "default": "s2n",
            "help": "Project name for report. Default: %(default)s",
    }, {
            "flags": ["--verbose"],
            "action": "store_true",
            "help": "verbose output",
    }]:
        flags = arg.pop("flags")
        pars.add_argument(*flags, **arg)
    return pars.parse_args()


def set_up_logging(verbose):
    if verbose:
        level = logging.DEBUG
    else:
        level = logging.WARNING
    logging.basicConfig(
        format="run-cbmc-proofs: %(message)s", level=level)


def task_pool_size():
    ret = os.cpu_count()
    if ret is None or ret < 3:
        return 1
    return ret - 2


def print_counter(counter):
    print(
        "\rConfiguring CBMC proofs: "
        "{complete:{width}} / {total:{width}}".format(
            **counter), end="", file=sys.stderr)


def get_proof_dirs(proof_root):
    for root, _, fyles in os.walk(proof_root):
        if "cbmc-batch.yaml" in fyles:
            yield root


def run_build(litani, jobs, proofs):
    cmd = [str(litani), "run-build"]
    if jobs:
        cmd.append("-j", jobs)
    if proofs:
        cmd.append("--pipelines")
        cmd.extend(proofs)

    logging.debug(" ".join(cmd))
    proc = subprocess.run(cmd)
    if proc.returncode:
        logging.error("Failed to run litani run-build")
        sys.exit(1)


def get_litani_path(proof_root):
    cmd = [
        "make",
        "PROOF_ROOT=%s" % proof_root,
        "-f", "Makefile.common",
        "litani-path",
    ]
    logging.debug(" ".join(cmd))
    proc = subprocess.run(cmd, universal_newlines=True, stdout=subprocess.PIPE)
    if proc.returncode:
        logging.error("Could not determine path to litani")
        sys.exit(1)
    return proc.stdout.strip()


async def configure_proof_dirs(queue, counter):
    while True:
        print_counter(counter)
        path = str(await queue.get())

        proc = await asyncio.create_subprocess_exec(
            "nice", "-n", "15", "make", "-B", "--quiet", "report", cwd=path)
        await proc.wait()
        counter["fail" if proc.returncode else "pass"].append(path)
        counter["complete"] += 1

        print_counter(counter)
        queue.task_done()


async def main():
    args = get_args()
    set_up_logging(args.verbose)

    proof_root = pathlib.Path(__file__).resolve().parent
    litani = get_litani_path(proof_root)

    if not args.no_standalone:
        cmd = [str(litani), "init", "--project", args.project_name]
        logging.debug(" ".join(cmd))
        proc = subprocess.run(cmd)
        if proc.returncode:
            logging.error("Failed to run litani init")
            sys.exit(1)

    proof_dirs = list(get_proof_dirs(proof_root))

    proof_queue = asyncio.Queue()
    for proof_dir in proof_dirs:
        proof_queue.put_nowait(proof_dir)

    counter = {
        "pass": [],
        "fail": [],
        "complete": 0,
        "total": len(proof_dirs),
        "width": int(math.log10(len(proof_dirs))) + 1
    }

    tasks = []
    for _ in range(task_pool_size()):
        task = asyncio.create_task(configure_proof_dirs(proof_queue, counter))
        tasks.append(task)

    await proof_queue.join()

    print_counter(counter)
    print("", file=sys.stderr)

    if counter["fail"]:
        logging.error(
            "Failed to configure the following proofs:\n%s", "\n".join(
                [str(f) for f in counter["fail"]]))

    if not args.no_standalone:
        run_build(litani, args.parallel_jobs, args.proofs)


if __name__ == "__main__":
    asyncio.run(main())
