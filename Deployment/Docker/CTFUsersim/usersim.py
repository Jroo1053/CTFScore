#!/usr/bin/env python3

"""
    CTF Particpant Simulator / Rough Approximatior
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

Registers an account with the ctfscore service and runs a variety of
attack tools against specified targets. Primmarly used for the following
purposes:

1. Generating relevent long term loads against test deployments of CTFscore.
2. Performing accuracy tests against the scoring system as, it also logs
the expected score to an attached sqlite DB.

"""
import argparse
from subprocess import Popen
import sys
import time
from argparse import ArgumentParser
import random
import socket
import datetime

SUPPORTED_ACTIONS = {
    "nikto": " -p 80 -h ",
    "nmap": " -p 80 --script=vuln -vvv ",
    "grafana-exploit": " -p 3000 -f /etc/shadow  -u "
}

ACTION_EXPECTED_SCORES ={
    "nikto": 8000,
    "nmap" : 4000,
    "grafana-exploit":1200
}

""""
SUPPORTED_ACTIONS = {
    "ping": " -c 3 "
}
ACTION_EXPECTED_SCORES = {
    "ping": 10
}
"""


parser = argparse.ArgumentParser(
    description="CTFScore User Simulator"
)
parser.add_argument(
    "-u", dest="score_url",
    required=True, help="URL for CTFScore Instance"
)
parser.add_argument(
    "-m", dest="max_attacks",
    required=False, help="Number Of Attacks To Perform", default=100
)
parser.add_argument(
    "-t", dest="target_assets",
    required=True, help="List Of Assets To Run Attacks Against", nargs="+"
)
parser.add_argument(
    "-v", dest="is_verbose",
    required=False, help="Toggles Verbose Mode", action="store_true"
)
parser.add_argument(
    "-d", dest="tool_delay",
    required=False, default=1, help="Number Of Seconds To Wait Between Attacks"
)
parser.add_argument(
    "-n", dest="no_register",
    required=False, default=False, help="Skip Account Regsitration", action="store_true"
)
parser.add_argument(
    "-o", dest="output_file",
    required=False, default="usersim.json", help="File To Log Expected Scores"
)
parser.add_argument(
    "-r", dest="robot_location",
    required=False, default="/scripts/robot/valid_register.robot", help="Path Login Test Case"
)
args = parser.parse_args()


def main():

    if args.no_register == False and create_account():
        run_attacks()
    elif args.no_register == True:
        run_attacks()
    print("Failed To Register Account With CTFScore, Exiting!")
    sys.exit(1)


def create_account():
    """
    Create an account and login to the system using the pre-existing robot
    test cases
    """
    register_command_args = 'robot -v "VALID ASSET ONE":"{}" -v "VALID ASSET TWO":"{}" {}'.format(
        get_ip(), get_hostname(), args.robot_location
    )
    register_proccess = Popen(
        register_command_args, shell=True)
    (output, err) = register_proccess.communicate()
    is_register_success = register_proccess.wait()
    if args.is_verbose:
        print(output)
    if is_register_success > 0:
        if args.is_verbose:
            print(err)
        return False
    return True


def run_attacks():
    for x in range(0, int(args.max_attacks)):
        time.sleep(args.tool_delay)
        target_tool, tool_args = random.choice(list(SUPPORTED_ACTIONS.items()))
        target_ip = random.choice(args.target_assets)
        tool_string = target_tool + (tool_args + target_ip)
        attack_procces = Popen(tool_string, shell=True)
        (output, err) = attack_procces.communicate()
        exit_code = attack_procces.wait()
        if exit_code > 0 and args.is_verbose:
            print(err)
            break
        score_pair = {
            "time": str(datetime.datetime.now()),
            "score": calc_score(target_tool),
            "action": tool_string

        }
        log_scores(score_pair)


def log_scores(score_pairs):
    with open(args.output_file, "a") as out_file:
        out_file.write(str(score_pairs) + "\n")


def calc_score(tool):
    return ACTION_EXPECTED_SCORES[tool]


def get_ip():
    # https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def get_hostname():
    with open("/etc/hostname") as host_file:
        return host_file.read()


if __name__ == "__main__":
    main()
