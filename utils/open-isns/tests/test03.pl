#!/usr/bin/perl
#
# Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
#
# This test case validates registration and unregistration.

push(@INC, ".");
require "harness.pl";

&test_prep("test03", @ARGV);

$server = &create_server;
$client = &create_client($server);

&isns_start_server($server);

&isns_enroll_client($client);
&isns_register_client($client, "initiator portal");

# Unregistering the portal should leave the iscsi node and
# portal group active, and move the portal to state limbo.
&isns_unregister_client($client, "portal=127.0.0.1:860");

# As the iscsi node goes away, so should the whole entity
&isns_unregister_client($client, "iscsi-name=isns.client1");

&isns_finish;
