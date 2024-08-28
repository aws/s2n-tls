# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

import argparse
import json
import boto3


class CriterionResult:
    def __init__(self, json_obj):
        self._json_obj = json_obj

    @property
    def _group_and_category(self):
        id_ = self._json_obj["id"]

        # The id is made up of the bench group and the category, separated by a /.
        # For example: handshake-ecdsa384/s2n-tls
        id_split = id_.split("/")
        assert len(id_split) == 2

        group = id_split[0]
        category = id_split[1]

        return group, category

    @property
    def group(self):
        group, category = self._group_and_category
        return group

    @property
    def category(self):
        group, category = self._group_and_category
        return category

    @property
    def mean_us(self):
        mean = self._json_obj["mean"]

        unit = mean["unit"]
        assert unit == "ns"

        # CloudWatch doesn't support nanoseconds, so the units are converted to microseconds.
        estimate_ns = mean["estimate"]
        estimate_us = estimate_ns / 1_000

        return estimate_us


class CriterionReader:
    def __init__(self, criterion_output_path):
        self.criterion_output_path = criterion_output_path

    def read_bench_results(self):
        with open(self.criterion_output_path, 'r') as output:
            for line in output.readlines():
                obj = json.loads(line)

                # Skip criterion output that isn't describing a benchmarking result.
                if obj.get("reason") != "benchmark-complete":
                    continue

                yield CriterionResult(obj)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog="criterion_to_cloudwatch",
        description="Emits CloudWatch metrics from criterion output.",
    )
    parser.add_argument(
        "--criterion_output_path",
        required=True,
        help="File containing criterion json output. Generated with cargo-criterion by specifying the "
             "`--message-format json` option.",
    )
    parser.add_argument(
        "--namespace",
        required=True,
        help="CloudWatch namespace to emit metrics to.",
    )
    parser.add_argument(
        "--platform",
        required=True,
        help="Specifies the platform dimension of the CloudWatch metrics.",
    )
    args = parser.parse_args()

    cloudwatch = boto3.client("cloudwatch")

    reader = CriterionReader(args.criterion_output_path)
    for result in reader.read_bench_results():
        print(f"Emitting {args.namespace} - {result.group}/{result.category} for {args.platform}: {result.mean_us}")

        cloudwatch.put_metric_data(
            Namespace=args.namespace,
            MetricData=[{
                "MetricName": result.group,
                "Dimensions": [
                    {
                        "Name": "Category",
                        "Value": result.category,
                    },
                    {
                        "Name": "Platform",
                        "Value": args.platform,
                    },
                ],
                "Value": result.mean_us,
                "Unit": "Microseconds",
            }],
        )
