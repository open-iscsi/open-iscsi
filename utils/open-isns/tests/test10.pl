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

&isns_prep_slow_test("test10", 20, @ARGV);

$server = &create_server({ "ESIMinInterval" => "10s" });
$client = &create_client($server);

&isns_start_server($server);

&isns_external_test($client, "tests/pauw3", "16");

&isns_stage("expired", "Waiting for ESI to come around");
&isns_idle(5);
&isns_verify_db($server);

&isns_external_test($client, "tests/pauw3", "-n", "16");

&isns_stage("expired", "Waiting for ESI to come around");
&isns_idle(5);
&isns_verify_db($server);

&isns_finish;
