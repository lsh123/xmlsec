#!/bin/sh
#
# Usage: parse_log_valgrind.sh <log-file>
#


# config
log=$1

if [ x"$log" = x ]; then
    echo "Usage: $0 <log-file>"
    exit 1
fi

grep 'ERROR SUMMARY' $log | sed 's/^[=0-9]* *//' | sort -u
grep 'definitely lost' $log | sed 's/^[=0-9]* *//' | sort -u
grep 'indirectly lost' $log | sed 's/^[=0-9]* *//' | sort -u
grep 'possibly lost' $log | sed 's/^[=0-9]* *//' | sort -u
grep 'still reachable' $log | sed 's/^[=0-9]* *//' | sort -u

