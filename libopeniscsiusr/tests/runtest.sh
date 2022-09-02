#!/bin/sh

if [ $# -eq 0 ];then
    echo "# No test cases defined"
    exit 1
fi

VALGRIND_ERR_RC=2
VALGRIND_OPTS="--quiet --leak-check=full \
               --show-reachable=no --show-possibly-lost=no \
               --trace-children=yes --error-exitcode=$VALGRIND_ERR_RC"

TEST_DIR="$(dirname "$0")"

for TEST; do
    echo
    TEST=${TEST##*/}
    echo "## RUN  '$TEST'"
    # shellcheck disable=SC2086
    valgrind $VALGRIND_OPTS "$TEST_DIR/$TEST"
    rc=$?
    if [ $rc -ne 0 ]; then
        if [ $rc -eq $VALGRIND_ERR_RC ];then
            echo
            echo "### Found memory leak"
        fi
        exit $rc
    fi
    echo "## PASS '$TEST'"
done

echo
echo "# All PASS"
