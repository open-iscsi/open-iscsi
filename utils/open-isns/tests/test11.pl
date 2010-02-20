#!/usr/bin/perl
#
# Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
#
# This test case validates registration and simple query of
# single client.

push(@INC, ".");
require "harness.pl";

# For now, this one will run w/o security only
push(@ARGV, '-i');

&test_prep("test11", @ARGV);

$server = &create_server;
$client = &create_client($server);

&isns_start_server($server);

&isns_external_test($client, "tests/pauw4");

&isns_finish;
