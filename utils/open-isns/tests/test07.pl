#!/usr/bin/perl
#
# Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
#
# This test case validates that the server discards portals
# that do not respond to ESI messages

push(@INC, ".");
require "harness.pl";

&isns_prep_slow_test("test07", 30, @ARGV);

$server = &create_server({ "ESIMinInterval" => "5s" });
$client = &create_client($server);

&isns_start_server($server);

# 1: Enroll the client
&isns_enroll_client($client);

# 2: Register a simple initiator with one portal
&isns_register_client($client, "initiator portal,esi-port=65535,esi-interval=5");

&isns_stage("expired", "Waiting for ESI to expire (~15 sec)");
&isns_idle(15);
&isns_verify_db($server);

# 3: Register a simple initiator with two portals, one with ESI and one without.
# When the ESI monitored portal expires, this should still take down
# the whole network entity.
&isns_register_client($client, "initiator portal,esi-port=65535,esi-interval=5 portal=127.0.0.1:1");

&isns_stage("expired", "Waiting for ESI to expire (~15 sec)");
&isns_idle(15);
&isns_verify_db($server);

&isns_finish;
