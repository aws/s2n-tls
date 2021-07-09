#!/usr/bin/env python3
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


import argparse
import asyncio
import logging
import math
import os
import pathlib
import subprocess
import sys


DESCRIPTION = "Configure and run all CBMC proofs in parallel"

# Keep the epilog hard-wrapped at 70 characters, as it gets printed
# verbatim in the terminal. 70 characters stops here --------------> |
EPILOG = """
This tool automates the process of running `make report` in each of
the CBMC proof directories. The tool calculates the dependency graph
of all tasks needed to build, run, and report on all the proofs, and
executes these tasks in parallel.

The tool is roughly equivalent to doing this:

        litani init --project "my-cool-project";

        find . -name cbmc-proof.txt | while read -r proof; do
            pushd $(dirname ${proof});

            # The `make _report` rule adds a single proof to litani
            # without running it
            make _report;

            popd;
        done

        litani run-build;

except that it is much faster and provides some convenience options.
The CBMC CI runs this script with no arguments to build and run all
proofs in parallel. The value of "my-cool-project" is taken from the
PROJECT_NAME variable in Makefile-project-defines.

The --no-standalone argument omits the `litani init` and `litani
run-build`; use it when you want to add additional proof jobs, not
just the CBMC ones. In that case, you would run `litani init`
yourself; then run `run-cbmc-proofs --no-standalone`; add any
additional jobs that you want to execute with `litani add-job`; and
finally run `litani run-build`.
"""


def get_project_name():
    cmd = [
        "make",
        "-f", "Makefile.common",
        "echo-project-name",
    ]
    logging.debug(" ".join(cmd))
    proc = subprocess.run(cmd, universal_newlines=True, stdout=subprocess.PIPE)
    if proc.returncode:
        logging.critical("could not run make to determine project name")
        sys.exit(1)
    if not proc.stdout.strip():
        logging.warning(
            "project name has not been set; using generic name instead. "
            "Set the PROJECT_NAME value in Makefile-project-defines to "
            "remove this warning")
        return "<PROJECT NAME HERE>"
    return proc.stdout.strip()


def get_args():
    pars = argparse.ArgumentParser(
        description=DESCRIPTION, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
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
            "metavar": "DIR",
            "help": "only run proof in directory DIR (can pass more than one)",
    }, {
            "flags": ["--project-name"],
            "metavar": "NAME",
            "default": get_project_name(),
            "help": "project name for report. Default: %(default)s",
    }, {
            "flags": ["--proof-marker"],
            "metavar": "FILE",
            "default": "cbmc-proof.txt",
            "help": (
                "name of file that marks proof directories. Default: "
                "%(default)s"),
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


def get_proof_dirs(proof_root, proof_list, proof_marker):
    if proof_list is not None:
        proofs_remaining = list(proof_list)
    else:
        proofs_remaining = []

    for root, _, fyles in os.walk(proof_root):
        proof_name = str(pathlib.Path(root).name)
        if proof_list and proof_name not in proof_list:
            continue
        if proof_list and proof_name in proofs_remaining:
            proofs_remaining.remove(proof_name)
        if proof_marker in fyles:
            yield root

    if proofs_remaining:
        logging.critical(
            "The following proofs were not found: %s",
            ", ".join(proofs_remaining))
        sys.exit(1)


def run_build(litani, jobs):
    cmd = [str(litani), "run-build"]
    if jobs:
        cmd.extend(["-j", str(jobs)])

    logging.debug(" ".join(cmd))
    proc = subprocess.run(cmd)
    if proc.returncode:
        logging.critical("Failed to run litani run-build")
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
        logging.critical("Could not determine path to litani")
        sys.exit(1)
    return proc.stdout.strip()


async def configure_proof_dirs(queue, counter):
    while True:
        print_counter(counter)
        path = str(await queue.get())

        proc = await asyncio.create_subprocess_exec(
            "nice", "-n", "15", "make", "-B", "--quiet", "_report", cwd=path)
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
            logging.critical("Failed to run litani init")
            sys.exit(1)

    proof_dirs = list(get_proof_dirs(
        proof_root, args.proofs, args.proof_marker))
    if not proof_dirs:
        logging.critical("No proof directories found")
        sys.exit(1)

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
        task = asyncio.create_task(configure_proof_dirs(
            proof_queue, counter))
        tasks.append(task)

    await proof_queue.join()

    print_counter(counter)
    print("", file=sys.stderr)

    if counter["fail"]:
        logging.critical(
            "Failed to configure the following proofs:\n%s", "\n".join(
                [str(f) for f in counter["fail"]]))

    if not args.no_standalone:
        run_build(litani, args.parallel_jobs)


if __name__ == "__main__":
    asyncio.run(main())
