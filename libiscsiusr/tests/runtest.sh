#!/bin/bash
TESTS="test_session"

VALGRIND_ERR_RC=2
VALGRIND_OPTS="--quiet --leak-check=full \
               --show-reachable=no --show-possibly-lost=no \
               --trace-children=yes --error-exitcode=$VALGRIND_ERR_RC"

TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

for TEST in $TESTS; do
    echo
    echo "## Running test '$TEST'"
    valgrind $VALGRIND_OPTS $TEST_DIR/$TEST
    rc=$?
    if [ $rc -ne 0 ]; then
        if [ $rc -eq $VALGRIND_ERR_RC ];then
            echo
            echo "### Found memory leak"
            exit $rc
        fi
        exit $rc
    fi
done

echo
echo "# PASS"
