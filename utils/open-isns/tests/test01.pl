#!/usr/bin/perl
#
# Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
#
# This test case validates registration and simple query of
# single client.

push(@INC, ".");
require "harness.pl";

&test_prep("test01", @ARGV);

$server = &create_server;
$client = &create_client($server);

&isns_start_server($server);

# 1: Enroll the test client
&isns_enroll_client($client);

# 2: Register an initiator with default portal
&isns_register_client($client, "initiator portal");

# 3: Run a simple query
&isns_query_objects($client, "eid");

# 99: Unregister client
&isns_unregister_client("99-unregistration", $client);

&isns_finish;
