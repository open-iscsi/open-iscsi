#!/bin/sh

if [ -z "${TESTS:-}" ]; then
    echo "# No test cases defined"
    exit 1
fi

VALGRIND_ERR_RC=2
case "$0" in
*/*) TEST_DIR=${0%/*} ;;
*) TEST_DIR=. ;;
esac
TEST_DIR=$(cd "$TEST_DIR" || exit; pwd)

for test_path in $TESTS; do
    echo
    TEST=${test_path##*/}
    echo "## RUN  '$TEST'"
    valgrind --quiet --leak-check=full --show-reachable=no \
        --show-possibly-lost=no --trace-children=yes \
        --error-exitcode="$VALGRIND_ERR_RC" "$TEST_DIR/$TEST"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        if [ "$rc" -eq "$VALGRIND_ERR_RC" ]; then
            echo
            echo "### Found memory leak"
            exit "$rc"
        fi
        exit "$rc"
    fi
    echo "## PASS '$TEST'"
done

echo
echo "# All PASS"
