#!/usr/bin/perl
#
# Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
#
# This test case verifies entity expiry

push(@INC, ".");
require "harness.pl";

&isns_prep_slow_test("test05", 30, @ARGV);

$server = &create_server({ "RegistrationPeriod" => "20s" });
$client = &create_client($server);

&isns_start_server($server);

&isns_enroll_client($client);
&isns_register_client($client, "initiator portal");

&isns_stage("expired", "Waiting for registration period to expire (25s)");
&isns_idle(25);
&isns_verify_db($server);

&isns_finish;

