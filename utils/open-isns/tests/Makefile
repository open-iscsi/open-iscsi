#
# Simple makefile to run regression tests, and to
# document how to run them.

#
# Each test case is a perl script, testXX.pl. Run as
# 	perl testXX.pl
# Optionally followed by
#  -q	quiet - just print a header line, and the overall result
#  -v	verbose - display more detailed information, including the
#	commands being run
#  -f	fast - skip tests that take more than 15 seconds
#
# The default is to be slightly verbose, and display a comment
# about each stage of the test.

# All test related data is kept in /tmp/isns-test, with a
# subdirectory for each test.
# For instance, test01 will create
#  /tmp/isns-test/test01/server0
#  /tmp/isns-test/test01/client1
#  /tmp/isns-test/test01/dump
#
# The server and client directories will contain configuration
# data, logfiles, and (for the server) the Unix socket, the
# PID file, and the database.
#
# The dump directory contains snapshots of the on-disk database
# for each test stage (if the test stage involves a verification
# of the database).

tests:
	@for test in test*.pl; do \
		perl $$test -q; \
	done

quick:
	@for test in test*.pl; do \
		perl $$test -q --fast; \
	done
