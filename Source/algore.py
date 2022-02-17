"""
Advanced CTF Scoring System - Scoring Algorithm Tester

    Copyright (C) 2021  Joseph Frary

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""

from argparse import ArgumentParser
from datetime import time, timedelta
from os import stat_result
import sys
from Lib.utils import parse_logs, get_config_opts
from Lib.models import LogSource, AlertFields, DictObj
from Lib.scoring import alien_vault_USM_algor, naive_algor
from timeit import default_timer as timer
from datetime import timedelta
import logging

DEFAULT_LOG_PATH = ""

parser = ArgumentParser(
    description="Advanced CTF Scoring System - Scoring Algorithm Tester"
)
parser = ArgumentParser(
    description="Advanced CTF Scoring System - Log Aggregator / Processor")
parser.add_argument("-c", "--config-file", dest="config_file_path",
                    help="Select location of config file", metavar="FILE")
parser.add_argument("-v", "--verbose", dest="is_verbose",
                    help="Verbose Output", action="store_true")
parser.set_defaults(is_verbose=False)
args, _ = parser.parse_known_args()


logging.basicConfig(
    filename="algoretester.log", encoding="utf-8",
    level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')


def main():
    """"
    Inits scoring algorithm tester
    """
    opts = load_config()
    if args.is_verbose:
        print("Loaded Config Files")
        print(opts)
    if not opts:
        sys.exit("Config file could not be located")
    opt_wrap = DictObj(opts)
    log_sources = []
    # Enter Main Loop
    for ids_source in opt_wrap.ids_options:
        log_sources.append(LogSource(
            name=ids_source.ids.name,
            path=ids_source.ids.log_file_format.path,
            max_alerts=ids_source.ids.max_alerts,
            fields=ids_source.ids.log_file_format.fields,
            reliability=ids_source.ids.reliability
        ))
    if args.is_verbose:
        print(log_sources)
    events = []

    for source in log_sources:
        events.append(parse_logs(source))

    categories = []
    for source in events:
        for alert in source:
            categories.append(alert.category)
    uniq_cats = set(categories)
    print("Unique Event Categories Available:", uniq_cats)
    """
    Run results through all of the scoring algorithms and collect results
    """
    start_naive = timer()
    naive_algor(events)
    end_naive = timer()
    print("(Naive) Compute Time :",timedelta(seconds=end_naive-start_naive))
    start_USM = timer()
    alien_vault_USM_algor(events,opt_wrap.asset_options)
    end_USM = timer()
    print("(USM) Compute Time :",timedelta(seconds=end_USM-start_USM))


def load_config():
    """
    Loads a config from the sources set in the args and returns a dict of
    options
    """
    if args.config_file_path:
        try:
            opts = get_config_opts(args.config_file_path)
            logging.info("Found config file at %s", args.config_file_path)
            return opts
        except (FileNotFoundError, IsADirectoryError, IOError,KeyError):
            logging.warning(
                "Failed to load config from environment var, trying default path")
            # Try to load from default file

if __name__ == "__main__":
    main()