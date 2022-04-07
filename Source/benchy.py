#!/usr/bin/env python3

import argparse
from datetime import datetime, timedelta

import json
from statistics import mean

from orjson import loads


TIME_FORMAT = "%H:%M:%S.%f"

def main():
    parser = argparse.ArgumentParser(
        description="Log Aggregator Benchmark Viewer"
    )
    parser.add_argument(
        "-f", dest="bench_file",
        required=True,
    )
    args = parser.parse_args()
    try:
        if hasattr(args, "bench_file"):
            load_stats(args.bench_file)
    except KeyboardInterrupt:
        return


def load_stats(target_file):
    data_points = []
    average_parse_time = 0.0
    with open(target_file, "r") as read_file:
        for line in read_file:
            data_points.append(json.loads(line))
    total_alerts = sum([x["event_count"] for x in data_points])
    print("Total Alerts: ",total_alerts)
    print("-" * 60)
    parsers = set([x["json_parser"] for x in data_points])
    for parser in parsers:
        parser_total = sum([x["event_count"] for x in data_points if x["json_parser"] == parser ])
        parse_times = [datetime.strptime(x["parse_time"],TIME_FORMAT) for x in data_points if x["json_parser"] == parser]
        parse_deltas = [timedelta(seconds=y.second,microseconds=y.microsecond) for y in parse_times]
        avg_parse_delta = round(mean([i.microseconds / 1000000 for i in parse_deltas]),4)
        max_parse_delta = round(max([i.microseconds / 1000000 for i in parse_deltas]),4)
        min_parse_delta = round(min([i.microseconds / 1000000 for i in parse_deltas]),4)
        print("Number Of Alerts Parsed By {}: {}".format(parser,parser_total))
        print("Minimum Parse Duration (secs) ({}): {}".format(parser,min_parse_delta))
        print("Average Parse Duration (secs) ({}): {}".format(parser,avg_parse_delta))
        print("Maximum Parse Duration (secs) ({}): {}".format(parser,max_parse_delta))
        print("-" * 60)


if __name__ == "__main__":
    main()
