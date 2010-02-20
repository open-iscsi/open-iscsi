#!/usr/bin/perl
#
# Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
#
# This test case verifies that the database remains intact
# across server restarts.

push(@INC, ".");
require "harness.pl";

&test_prep("test04", @ARGV);

$server = &create_server;
$client = &create_client($server);

&isns_start_server($server);

&isns_enroll_client($client);
&isns_register_client($client, "initiator portal");

# Restart the server, and make sure it still displays
# the database properly
&isns_stage("restart", "Restarting server process");
&isns_restart_server($server);
&isns_verify_db($server);

# Run a simple query
&isns_query_objects($client, "iscsi-name");

&isns_finish;
