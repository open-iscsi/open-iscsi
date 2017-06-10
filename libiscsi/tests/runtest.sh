#!/bin/bash
TESTS="test_discovery_sendtargets test_discovery_firmware"
TESTS="$TESTS test_set_auth test_get_auth"
TESTS="$TESTS test_login test_logout test_params"
TESTS="$TESTS test_fw_get_network_config test_fw_get_initiator_name"

OPT_TEST="test_discovery_firmware"
OPT_TEST="$OPT_TEST test_fw_get_network_config test_fw_get_initiator_name"

VALGRIND_ERR_RC=2
VALGRIND_OPTS="--quiet --leak-check=full \
               --show-reachable=no --show-possibly-lost=no \
               --trace-children=yes --error-exitcode=$VALGRIND_ERR_RC"

TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

for TEST in $TESTS; do
    echo;
    echo "## Running test '$TEST'";
    valgrind $VALGRIND_OPTS $TEST_DIR/$TEST;
    rc=$?
    if [ $rc -ne 0 ]; then
        if [ $rc -eq $VALGRIND_ERR_RC ];then
            echo;
            echo "### Found memory leak";
            exit $rc;
        fi
        if [ "CHK$(echo $OPT_TEST|grep $TEST)" != "CHK" ];then
            echo;
            echo "### Optional test '$TEST' failed";
            continue;
        fi
        exit $rc;
    fi
done

echo;
echo "# PASS"
