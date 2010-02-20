#!/usr/bin/perl
#
# Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
#
# This test case validates DevAttrReg replace mode.

push(@INC, ".");
require "harness.pl";

&test_prep("test06", @ARGV);

$server = &create_server;
$client = &create_client($server);

&isns_start_server($server);

# 1: Enroll the client
&isns_enroll_client($client);

# 2: Register a simple initiator with one portal
&isns_register_client($client, "initiator portal");

$eid = &isns_query_eid($client);
unless ($eid) {
	&isns_die("Cannot obtain entity ID");
}

# Now replace the portal with different values
&isns_register_client($client, "--replace entity=$eid initiator portal=192.168.1.1:iscsi");
&isns_register_client($client, "--replace entity=$eid initiator portal=192.168.1.2:iscsi");

&isns_register_domain($client, "member-name=isns.client1");

# Replace our registration once more. Now the object index of the
# initiator should not change, since it's a domain member now.
&isns_register_client($client, "--replace entity=$eid initiator portal=192.168.1.1:iscsi");

# Make the portal a domain member too. Now even the portal index should stay
# the same. Note that we do not replace the whole entity now, but just the
# portal
&isns_register_domain($client, "dd-id=1 member-addr=192.168.1.1 member-port=860");
&isns_register_client($client, "--replace --key portal=192.168.1.1:iscsi portal=192.168.1.2:iscsi");
&isns_register_client($client, "--replace --key portal=192.168.1.2:iscsi portal=192.168.1.1:iscsi");

# Now unregister the whole client, and re-register.
# Portal and client index should remain the same
&isns_unregister_client($client, "eid=$eid");
&isns_register_client($client, "initiator portal=192.168.1.1:iscsi");

&isns_finish;
