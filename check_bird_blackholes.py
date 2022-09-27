#!/usr/bin/python3
#
# This script is licensed under GPL-2+
#
'''Nagios/icinga plugin ensuring a set of Bird tables are empty.

This is used for monitoring within the Bird networking daemon some tables that
have a special purpose and which should be empty in normal circumstances. For
example, tables where blackhole routes are inserted with ip-route and then
learned automatically by Bird.
'''

import sys
import os
import argparse
import subprocess

# Nagios plugin exit codes
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

birdc = '/usr/sbin/birdc'


class WarningReached(Exception):
    pass


class CriticalReached(Exception):
    pass


class ExecutionError(Exception):
    pass


def debug(*args):
    if os.environ.get('DEBUG', None):
        print(f"debug: {args}")


def check_bird_table_empty(table, warn, crit):
    cmd = [birdc, '-r', '-v', 'show', 'route', 'table', table]
    debug("running command: ", cmd)

    res = subprocess.run(cmd, encoding='utf8',
                         capture_output=True, check=True)

    output = res.stdout.split("\n")[2:]

    debug("output line count: ", len(output))
    debug("output lines: ", output)

    # Error codes with bird start with 8000
    if int(output[0][0:4]) > 8000:
        raise ExecutionError(' '.join(output))

    routes = [r for r in output if r and not r.startswith('1007-')]
    debug("found routes: ", routes)

    if crit is not None and len(routes) >= crit:
        raise CriticalReached(f"Routes found in table {table}: {len(routes)}")
    if warn is not None and len(routes) >= warn:
        raise WarningReached(f"Routes found in table {table}: {len(routes)}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Ensure a set of Bird tables are empty')
    parser.add_argument('-w', '--warning-threshold', type=int,
                        help='Number of routes in each table at which the check enters warning state')
    parser.add_argument('-c', '--critical-threshold', type=int,
                        help='Number of routes in each table at which the check enters critical state')
    parser.add_argument('tables', nargs='+', help='Bird tables that get inspected')

    args = parser.parse_args()

    tables = args.tables
    if len(tables) == 0:
        print("error: no table names were specified")
        sys.exit(UNKNOWN)

    debug("arguments: warning=", args.warning_threshold, " critical=", args.critical_threshold)

    check_state = OK
    for t in tables:
        try:
            check_bird_table_empty(t, warn=args.warning_threshold, crit=args.critical_threshold)
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
