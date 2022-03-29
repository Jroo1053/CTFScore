"""

    Advanced CTF Scoring System - Log Aggregator./ Forwarder
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
#pylint: disable=no-member

from argparse import ArgumentParser
import sched
import time
import sys
import logging

from Lib.utils import get_config_opts, parse_logs
from Lib.models import APIConnection, DictObj, LogSource


try:
    logging.basicConfig(
        filename="/var/log/ctfscorelog/logger.log",
        level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
except FileNotFoundError:
    logging.basicConfig(
        filename="logger.log",
        level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')


logging.info("Started log aggregator")

parser = ArgumentParser(
    description="Advanced CTF Scoring System - Log Aggregator / Processor")
parser.add_argument("-c", "--config-file", dest="config_file_path",
                    help="Select location of config file", metavar="FILE")
parser.add_argument("-v", "--verbose", dest="is_verbose",
                    help="Verbose Output", action="store_true")
parser.add_argument("-b", "--benchmark", dest="is_benchmark",
                    help="Enable The Collection of Enhanced Performance Stats",
                    default=False, action="store_true")
parser.add_argument("-r", "--random-json", dest="is_rand_json",
                    help="Use JSON Parsers Randomly", default=False,
                    action="store_true")
parser.set_defaults(is_verbose=False)
args, _ = parser.parse_known_args()
task_loop = sched.scheduler(time.time, time.sleep)
DEFAULT_LOG_PATH = "/etc/ctfscorelog/config.yml"


def main():
    """"
    Inits logger and starts main event loop
    """
    opts = load_config()
    if args.is_verbose:
        print("Loaded Config Files")
        print(opts)
    if not opts:
        sys.exit("Config file could not be located")

    # Build api connection object for later use
    opt_wrap = DictObj(opts)
    try:
        api_connection = APIConnection(
            opt_wrap.global_options.api_url,
            opt_wrap.global_options.polling_rate,
            opt_wrap.global_options.api_id_file,
            opt_wrap.global_options.api_key_file,
            opt_wrap.global_options.api_status_endpoint,
            opt_wrap.global_options.api_forward_event_endpoint,
            opt_wrap.global_options.api_max_retries,
            opt_wrap.global_options.api_is_enabled
        )
    except FileNotFoundError:
        logging.error("The api key or id file was not found ")
        sys.exit("The api key or id file was not found")
    except IOError:
        logging.error(
            "A file IO error occurred when reading the api key or id file ")
        sys.exit("Unable to read api files")
    except ValueError as api_error:
        logging.error(
            ("The api %s are invalid, exiting! ", api_error.args))
        sys.exit("Invalid api connection files")

    log_sources = []
    # Enter Main Loop
    try:
        for ids_source in opt_wrap.ids_options:
            log_sources.append(LogSource(
                name=ids_source.ids.name,
                path=ids_source.ids.log_file_format.path,
                max_alerts=ids_source.ids.max_alerts,
                fields=ids_source.ids.log_file_format.fields,
                reliability=ids_source.ids.reliability
            ))
    except AttributeError:
        logging.error(
            ("Failed to load IDS from config: ", ids_source.ids.name))
        sys.exit(("Failed to load IDS: ", ids_source.ids.name))
    if args.is_verbose:
        print(log_sources)
    while True:
        # Exit event loop if there are no valid sources
        valid_sources = len(list(filter(lambda source: source.is_valid,
                                        log_sources)))
        if valid_sources:
            task_loop.enter(
                opt_wrap.global_options.polling_rate / 100,
                1, event_loop, argument=(api_connection, log_sources))
            task_loop.run()
        else:
            logging.error("No valid log sources found, exiting!")
            sys.exit("No valid log sources found")


def event_loop(api_connection, log_sources):
    """
    The sched module doesn't handle returning values so this func is a quick
    work around
    """
    events = read_events(log_sources=log_sources)
    if api_connection.is_enabled:
        if len(events) > 0:
            if args.is_verbose:
                api_connection.forward_IDS_alerts(events, is_verbose=True)
            else:
                api_connection.forward_IDS_alerts(events)


def read_events(log_sources):
    """Reads a log source and returns an array of alert objects"""
    if args.is_verbose:
        print("Reading events from logs sources")
    lastestevents = []
    for source in log_sources:
        lastestevents.append(parse_logs(source,
                                        is_benchmark=args.is_benchmark,
                                        is_rand_json=args.is_rand_json
                                        ))
    if args.is_verbose:
        print(lastestevents)
    return lastestevents


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
        except (FileNotFoundError, IsADirectoryError, IOError, KeyError):
            logging.warning(
                "Failed to load config from environment var, trying default path")
            # Try to load from default file
            try:
                opts = get_config_opts(DEFAULT_LOG_PATH)
                if opts:
                    logging.info("Loaded from default path: %s",
                                 DEFAULT_LOG_PATH)
                return opts
            except (FileNotFoundError, IsADirectoryError, IOError, KeyError):
                logging.error("Failed to load both config files, exiting!")
                sys.exit("Config file could not be loaded")
    else:
        try:
            opts = get_config_opts(DEFAULT_LOG_PATH)
            return opts
        except (FileNotFoundError, IsADirectoryError, IOError):
            logging.error(
                "Failed to load config from default path, and no other file was specified")
            sys.exit("Config file could not be loaded")


if __name__ == "__main__":
    main()
