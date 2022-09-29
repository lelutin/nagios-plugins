#!/usr/bin/python3
#
# This script is licensed under GPL-2+
#
# Because of the command that we're using to grab information, this script
# needs to be run as root
#
'''Nagios/icinga plugin ensuring that some nftables set are empty.

This is used for monitoring some firewall IP sets that have a special purpose
and which should be empty in normal circumstances. For example, sets that are
used for matching IPs that should get completely blocked by the firewall.
'''

import sys
import os
import argparse
import subprocess
import json
from datetime import datetime, timedelta

# Nagios plugin exit codes
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

nft = '/usr/sbin/nft'


class WarningReached(Exception):
    pass


class CriticalReached(Exception):
    pass


class ExecutionError(Exception):
    pass


def debug(*args):
    if os.environ.get('DEBUG', None):
        print(f"debug: {args}")


def stringify_element(elem) -> str:
    """Change set elements to strings.

    Some elements returned by nftables may be dictionaries when they use
    additional options. We want to transform those into human-readable strings
    that the check can output as its result.
    """
    if type(elem) == str:
        return elem

    formatted_elem = f"{elem['elem']['val']}"

    if elem['elem'].get("expires", None) is not None:
        expires = datetime.now() + timedelta(seconds=elem['elem']['expires'])
        formatted_elem += f" expires at {expires}"

    return formatted_elem


def check_nft_set_empty(set_name, warn, crit):
    cmd = [nft, '-j', 'list', 'set', set_name]
    debug("running command: ", cmd)

    res = subprocess.run(cmd, encoding='utf8',
                         capture_output=True, check=True)

    output = json.loads(res.stdout)['nftables'][1]['set'].get('elem', [])

    elements = [stringify_element(x) for x in output]

    debug("set element count: ", len(elements))
    debug("found elements: ", elements)

    if crit is not None and len(elements) >= crit:
        raise CriticalReached(f"Elements found in firewall set {set_name}: {', '.join(elements)}")
    if warn is not None and len(elements) >= warn:
        raise WarningReached(f"Elements found in firewall set {set_name}: {', '.join(elements)}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Ensure some nftables sets are empty')
    parser.add_argument('-w', '--warning-threshold', type=int,
                        help='Number of elements in each set at which the check enters warning state')
    parser.add_argument('-c', '--critical-threshold', type=int,
                        help='Number of elements in each set at which the check enters critical state')
    parser.add_argument(
        'sets', nargs='+',
        help='Names of nftables sets that get inspected. Each name should be a full specification that nftables understands, e.g. "[family] table_name set_name"')  # noqa: E501

    args = parser.parse_args()

    sets = args.sets
    if len(sets) == 0:
        print("error: no set names were specified")
        sys.exit(UNKNOWN)

    debug("arguments: warning=", args.warning_threshold, " critical=", args.critical_threshold)

    check_state = OK
    for s in sets:
        try:
            check_nft_set_empty(s, warn=args.warning_threshold, crit=args.critical_threshold)
        except (subprocess.CalledProcessError, ExecutionError) as e:
            print(f"error: {e}")
            sys.exit(UNKNOWN)
        except WarningReached as e:
            print(e)
            if check_state < WARNING:
                check_state = WARNING
        except CriticalReached as e:
            print(e)
            if check_state < CRITICAL:
                check_state = CRITICAL

    sys.exit(check_state)
