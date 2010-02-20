#!/usr/bin/perl
#
# Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
#
# This test case validates registration and simple query of
# two clients, and simple DD functionality.

push(@INC, ".");
require "harness.pl";

&test_prep("test02", @ARGV);

$server = &create_server;
$client1 = &create_client($server, "127.1.0.1");
$client2 = &create_client($server, "127.1.0.2");

&isns_start_server($server);

# 1: Enroll the client1
&isns_enroll_client($client1);

# 2: Enroll the client1
&isns_enroll_client($client2, "node-type=target");

&isns_stage("registration", "Registering both clients");
&__isns_register_client($client1, "initiator portal");
&__isns_register_client($client2, "target portal");
&isns_verify_db($server);

# Now each of the two clients should just see
# itself
&isns_query_objects($client1, "eid");
&isns_query_objects($client2, "eid");

# Register a DD linking the two nodes
&isns_register_domain($client1, "member-name=isns.client1", "member-name=isns.client2");

# Now the clients should see each other
&isns_query_objects($client1, "eid");
&isns_query_objects($client2, "eid");

# Initiator querying for target:
&isns_query_objects($client1, "iscsi-node-type=Target");

# Add another member to this DD, and re-add client2 (making
# sure the server doesn't generate dupes)
&isns_register_domain($client1, "dd-id=1", "member-name=isns.client2", "member-name=iqn.com.foobar:disk1");

# Query the list of DDs we're a member of
&isns_query_objects($client1, "dd-id");

# Remove some entries from the DD
&isns_deregister_domain($client1, "1", "member-iscsi-idx=10");
&isns_deregister_domain($client1, "1", "member-name=iqn.com.foobar:disk1");
&isns_register_domain($client1, "dd-id=1", "member-name=isns.client2");
&isns_deregister_domain($client1, "1");

&isns_finish;
