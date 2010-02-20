#!/usr/bin/perl

use Getopt::Long;

$__isns_verbose = 1;
$__isns_security = 1;

$__isns_bin = "../";
$__isns_seq = 0;
$__isns_test_base = '/tmp/isns-test';
$__isns_test_dir = '/tmp/isns-test/test';
$__isns_stage = 1;
$__isns_test_data = '';
$__isns_test_dump = '';
$__isns_passed = 0;
$__isns_failed = 0;
$__isns_warned = 0;
@__isns_servers = ();

%__isns_ignore_tag = (
	"0004"	=> 1,		# Timestamp
	"0603v"	=> 1,		# DSA public key
);

sub isns_fail {
	
	print "*** FAILURE ***\n";
	$__isns_failed++;

	my $line;
	foreach $line (@_) {
		print "*** $line ***\n";
	}
}

sub isns_pass {

	print "*** SUCCESS ***\n" if ($__isns_verbose > 1);
	$__isns_passed++;
}

sub isns_warn {

	printf "*** WARNING: %s ***\n", join(' ', @_);
	$__isns_warned++;
}

sub isns_die {

	printf "*** TERMINAL FAILURE: %s ***\n", join(' ', @_);
	$__isns_failed++;

	&isns_finish;
	die "Test aborted\n";
}

sub isns_finish {

	my $pid;
	foreach $pid (@__isns_servers) {
		kill 15, $pid or &isns_warn("Cannot kill server process (pid=$pid): $!\n");
	}

	&isns_report;
}

sub isns_report {

	print "*** Test $__isns_test_name complete.";
	print " PASSED: $__isns_passed" if ($__isns_passed);
	print " FAILED: $__isns_failed" if ($__isns_failed);
	print " WARNINGS: $__isns_warned" if ($__isns_warned);
	print " ***\n";
}

sub isns_info {

	print @_ if ($__isns_verbose > 1);
}

sub isns_notice {

	print @_ if ($__isns_verbose > 0);
}

sub isns_stage {

	local($name, @msg) = @_;

	if ($name =~ m/^[0-9]/o) {
		$__isns_stage_name = $name;
	} else {
		$__isns_stage_name = sprintf "%02d-%s",
			$__isns_stage++, $name;
	}
	&isns_notice("*** $__isns_stage_name: ", @msg, " ***\n");
}

sub build_config {

	local($src_file, $dst_file, *__subst) = @_;
	my $key;
	my $okey;
	my $value;
	my $sepa;
	my %subst;

	&isns_info("*** Building $src_file -> $dst_file\n");

	# Translate all keys to lower case.
	foreach $key (keys(%__subst)) {
		$value = $__subst{$key};
		$key =~ tr/A-Z/a-z/;
		$subst{$key} = $value;
	}
#	foreach $key (keys(%subst)) {
#		printf "  %s -> %s\n", $key, $subst{$key};
#	}

	open IN, "<$src_file" or die "$src_file: $!\n";
	open OUT, ">$dst_file" or die "$dst_file: $!\n";

	while (<IN>) {
		$line = $_;
		if (m:(\S+)(\s*=\s*)(.*):o) {
			($okey, $sepa, $value) = ($1, $2, $3);

			$key = $okey;
			$key =~ tr/A-Z/a-z/;

			if ($subst{$key}) {
				$line = "$okey$sepa$subst{$key}\n";
			}
		}

		# Ignore unconfigured lines.
		next if ($line =~ m/\@[A-Z_]*\@/o);
		print OUT $line;
	}
	close OUT;
	close IN;
}

sub get_config_value {
	local($cfg_file, $item_name) = @_;
	my $result;
	my $name;
	my $value;

	$item_name =~ tr/A-Z/a-z/;

	open IN, "<$cfg_file" or die "$cfg_file: $!\n";
	while (<IN>) {
		chop;
		($name, $value) = split(/\s+=\s+/, $_);

		$name =~ tr/A-Z/a-z/;
		if ($name eq $item_name) {
			$result = $value;
			last;
		}
	}
	close IN;

	return $result;
}

sub create_key {

	local($keyfile) = @_;

	if ($__isns_security) {
		&isns_info("*** Creating key at $keyfile\n");
		system "./genkey -fsk $keyfile 2048 >${keyfile}.log 2>&1";
	}
	return $keyfile;
}

sub create_server {

	local(*override) = @_;
	my %local_config;
	my $my_dir;
	my $handle;
	my $config;

	$handle = sprintf "server%d", $__isns_seq++;
	$my_dir = "$__isns_test_dir/${handle}";

	mkdir $my_dir, 0700 or die "Cannot create $my_dir: $!\n";

	$server_addr = "127.0.0.1:7770" unless ($server_addr);

	$config = "$my_dir/config";

	$local_config{"SourceName"} = "isns.$handle";
	$local_config{"Database"} = "$my_dir/database";
	$local_config{"BindAddress"} = "$server_addr";
	$local_config{"PIDFile"} = "$my_dir/pid";
	$local_config{"ControlSocket"} = "$my_dir/control";
	$local_config{"Security"} = $__isns_security;
	$local_config{"AuthKeyFile"} = &create_key("$my_dir/auth_key");

	foreach $key (keys(%override)) {
		$local_config{$key} = $override{$key};
	}

	&build_config('server.conf', $config, \%local_config);
	return $config;
}

sub create_client {

	local($server_config, $client_address) = @_;
	my %local_config;
	my $server_key;
	my $control_socket;
	my $server_addr;
	my $my_dir;
	my $handle;
	my $config;

	$handle = sprintf "client%d", $__isns_seq++;
	$my_dir = "$__isns_test_dir/${handle}";

	mkdir $my_dir, 0700 or die "Cannot create $my_dir: $!\n";

	$control_socket = &get_config_value($server_config, "ControlSocket");
	$server_addr = &get_config_value($server_config, "BindAddress");
	$server_addr = "127.0.0.1" unless ($server_addr);

	$config = "$my_dir/config";

	$local_config{"SourceName"} = "isns.$handle";
	$local_config{"AuthName"} = "$handle.isns-test.eu";
	$local_config{"ServerAddress"} = $server_addr;
	$local_config{"ControlSocket"} = $control_socket;
	$local_config{"BindAddress"} = $client_address if ($client_address);
	$local_config{"server_config"} = $server_config;
	$local_config{"Security"} = $__isns_security;
	$local_config{"AuthKeyFile"} = &create_key("$my_dir/auth_key");
	$local_config{"ServerKeyFile"} =
		&get_config_value($server_config, "AuthKeyFile") . ".pub";

	&build_config('client.conf', $config, \%local_config);

	$__isns_data{$config,"server_config"} = $server_config;
	$__isns_data{$config} = %local_config;
	return $config;
}

sub get_logfile {

	local($config) = @_;
	my $dir;

	$dir = $config;
	$dir =~ s|/+[^/]+$||o;

	return "$dir/logfile";
}

sub run_command {

	local(@cmd) = @_;
	my $status;
	my $cmd;

	$cmd = join(' ', @cmd);
	&isns_info("$cmd\n");

	system "$cmd";

	$status = $?;
	if ($status) {
		&isns_warn("Command failed, exit status $status");
		print "*** Command was: $cmd ***\n";
		return undef;
	}

	return 1;
}

sub isns_start_server {

	local($server_config) = @_;
	my $logfile;
	my $pidfile;
	my $pid;

	die "restart_server: missing server config argument!\n"
		unless(-f $server_config);
	$logfile = &get_logfile($server_config);
	$pidfile = &get_config_value($server_config, "PIDFile");

	&isns_info("*** Starting server (logging to $logfile)\n");

	$pid = fork();
	if ($pid) {
		my $retry;

		if ($pidfile) {
			for ($retry = 0; $retry < 5; $retry++) {
				last if (-f $pidfile);
				sleep 1;
			}
			$pid = `cat $pidfile` if ($pidfile);
			chop($pid);
		}
		&isns_info("*** Started server (pid=$pid) ***\n");
		push(@__isns_servers, $pid);
		return $pid;
	}

	&isns_info("${__isns_bin}isnsd -c $server_config -f -d all\n");
	exec "${__isns_bin}isnsd -c $server_config -f -d all >$logfile 2>&1 &"
		or die "Unable to run isnsd: $!\n";
}

sub isns_stop_server {

	local($pid) = @_;
	my @list;
	my $p;

	kill 15, $pid or &isns_warn("Cannot kill server process (pid=$pid): $!\n");
	foreach $p (@__isns_servers) {
		append(@list, $p) unless ($p == $pid);
	}
	@__isns_servers = @list;
}

sub isns_restart_server {

	local($pid, $server_config);

	if ($_[0] =~ m:^\d+$:o) {
		$pid = shift(@_);
	} else {
		if ($#__isns_servers < 0) {
			&isns_warn("isns_restart_server: no server running\n");
			return 0;
		}
		$pid = $__isns_servers[0];
	}
	$server_config = shift(@_);

	&isns_stop_server($pid);
	return &isns_start_server($server_config);
}

sub isns_verify_db {

	local($stage, $server_config);
	my $dump_file;
	my $data_file;

	if ($_[0] =~ m/^\d/o) {
		$stage = shift(@_);
	} else {
		$stage = $__isns_stage_name;
	}
	$server_config = shift(@_);

	die "Test case forgot to call test_prep" unless($__isns_test_data);

	$dump_file = "$__isns_test_dump/$stage";
	unless (&run_command("${__isns_bin}/isnsd -c $server_config --dump-db > $dump_file")) {
		&isns_fail;
		return 0;
	}

	# See if the reference data file exists. If it
	# doesn't, this means we're priming the test case.
	# Just copy the dump file.
	$data_file = "$__isns_test_data/$stage";
	unless (-f $data_file) {
		print "*** Saving database dump for stage $stage ***\n";
		mkdir $__isns_test_data, 0755;
		system "cp $dump_file $data_file";
		return 1;
	}

	&isns_info("*** Verifying database dump for stage $stage ***\n");
	if (&verify_dump($stage, $data_file, $dump_file)) {
		&isns_pass;
	} else {
		if ($__isns_verbose > 1) {
			system("diff -u -ITimestamp -I'DSA security key' $data_file $dump_file");
		}
		&isns_fail;
	}

	return 1;
}

sub verify_db {

	&isns_verify_db(@_);
}

sub verify_response {

	local($stage, $client_config) = @_;
	my $dump_file;
	my $data_file;

	die "Test case forgot to call test_prep" unless($__isns_test_data);

	$dump_file = &get_logfile($client_config);

	# See if the reference data file exists. If it
	# doesn't, this means we're priming the test case.
	# Just copy the dump file.
	$data_file = "$__isns_test_data/$stage";
	unless (-f $data_file) {
		print "*** Saving data for stage $stage ***\n";
		mkdir $__isns_test_data, 0755;
		system "cp $dump_file $data_file";
		return 1;
	}

	&isns_info("*** Verifying data for stage $stage ***\n");
	if (&verify_query($stage, $data_file, $dump_file)) {
		&isns_pass;
	} else {
		&isns_fail("Query response returns unexpected data");
		system "cp $dump_file $__isns_test_dump/$stage";
		print "*** Saved dump as $__isns_test_dump/$stage\n";
		print "*** Reference data in $data_file\n";
		if ($__isns_verbose > 1) {
			system("diff -u -ITimestamp -I'DSA security key' $data_file $dump_file");
		}
	}

	return 1;
}

sub verify_dump {

	local($stage, $data_file, $dump_file) = @_;
	my $line;
	my @dump;
	my @data;
	my @obj1;
	my @obj2;

	@dump = &load_dump($dump_file);
	@data = &load_dump($data_file);

	&skip_header(\@dump);
	&skip_header(\@data);

	while (1) {
		$line++;

		@obj1 = &get_next_object(\@dump);
		@obj2 = &get_next_object(\@data);

		last unless(@obj1 || @obj2);

		unless (@obj1 && @obj2) {
			print STDERR "*** $stage: Excess data at end of dump\n";
			return 0;
		}

		unless (&compare_objects(\@obj1, \@obj2)) {
			print STDERR "*** Object mismatch (object $line):\n";
			print STDERR "Expected:\n  ";
			print STDERR join("\n  ", @obj2), "\n";
			print STDERR "Got:\n  ";
			print STDERR join("\n  ", @obj1), "\n";
			return 0;
		}
	}

	if (@data) {
		print STDERR "*** $stage: Unexpected end of dump at line $line\n";
		return 0;
	}

	return 1;
}

sub skip_header {

	local(*list) = @_;
	local($_);

	while ($_ = shift(@list)) {
		last if (/^-/o);
	}
}

sub get_next_object {

	local(*list) = @_;
	local($_, $header, @result);
	my @tags;

	while ($_ = shift(@list)) {
		next if (/^-/o);
		if (/^\s+([0-9a-fv]+)\s+/o) {
			next if ($__isns_ignore_tag{$1});
			push(@tags, $_);
		} else {
			if (@result) {
				unshift(@list, $_);
				last;
			}
			push(@result, $_);
		}
		#print "### $_\n";
	}

	if (@tags) {
		push(@result, sort(@tags));
	}
	return @result;
}

sub compare_objects {

	local(*a, *b) = @_;
	local($i);

	return 0 unless ($#a == $#b);
	for ($i = 0; $i <= $#a; $i++) {
		return 0 unless ($a[$i] eq $b[$i]);
	}

	return 1;
}


sub verify_query {

	local($stage, $data_file, $dump_file) = @_;
	my $line;
	my @dump;
	my @data;

	@dump = &load_dump($dump_file);
	@data = &load_dump($data_file);

	while (@dump) {
		$line++;
		unless (@data) {
			print STDERR "*** $stage: Excess data in dump at line $line\n";
			return 0;
		}

		$a = shift(@dump);
		$b = shift(@data);
		if ($a =~ /^\S/o) {
			next if ($a eq $b);
			print STDERR "*** $stage: Mismatch at line $line ***\n";
			print STDERR "*** Found:    $a\n";
			print STDERR "*** Expected: $b\n";
			return 0;
		}

		($nix, $a_tag, $a_value) = split(/\s+/, $a, 3);
		($nix, $b_tag, $b_value) = split(/\s+/, $b, 3);
		if ($a_tag ne $b_tag) {
			print STDERR "*** $stage: Tag mismatch at line $line\n";
			print STDERR "*** Found:    $a\n";
			print STDERR "*** Expected: $b\n";
			return 0;
		}

		next if ($__isns_ignore_tag{$a_tag});
		if ($a_value ne $b_value) {
			print STDERR "*** $stage: Value mismatch at line $line (tag $a_tag)\n";
			print STDERR "*** Found:    $a\n";
			print STDERR "*** Expected: $b\n";
			return 0;
		}
	}

	if (@data) {
		print STDERR "*** $stage: Unexpected end of dump at line $line\n";
		return 0;
	}

	return 1;
}

sub load_dump {

	local($filename) = @_;
	my @result;

	open IN, $filename or die "Unable to open $filename: $!\n";
	while (<IN>) {
		chop;
		push(@result, $_);
	}
	close IN;
	return @result;
}


sub run_client {

	local($config, @args) = @_;
	my $logfile;
	my $cmd;

	$logfile = &get_logfile($config);

	$cmd = "${__isns_bin}/isnsadm -c $client_config " . join(' ', @args);
	if (&run_command("$cmd >$logfile")) {
		return $logfile;
	}
	return undef;
}

sub __isns_enroll_client {

	local($client_config, @extra_args) = @_;
	my $source_name;
	my $auth_name;
	my $auth_key;
	my @args;

	$source_name = &get_config_value($client_config, "SourceName");
	$auth_name = &get_config_value($client_config, "AuthName");
	$auth_key = &get_config_value($client_config, "AuthKeyFile");

	push(@args, "--local --enroll $auth_name node-name=$source_name");
	push(@args, " key=${auth_key}.pub") if ($auth_key);
	push(@args, @extra_args) if (@extra_args);

	&run_client($client_config, @args);
}

sub isns_enroll_client {

	local($client, @args) = @_;
	my $server;

	$server = $__isns_data{$client,"server_config"};
	&isns_stage("enroll", "Enrolling client");
	&__isns_enroll_client($client, @args);
	&verify_db($__isns_stage_name, $server);
}

sub enroll_client {

	print "*** Enrolling client ***\n";
	&__isns_enroll_client(@_);
}

sub __isns_register_client {

	local($client_config, @extra_args) = @_;
	my @args;

	push(@args, "--register");
	push(@args, @extra_args) if (@extra_args);

	&run_client($client_config, @args);
}

sub isns_register_client {

	local($client, @args) = @_;
	my $server;

	$server = $__isns_data{$client,"server_config"};
	&isns_stage("registration", "Registering client " . join(' ', @args));
	&__isns_register_client($client, @args);
	&verify_db($__isns_stage_name, $server);
}

sub register_client {

	print "*** Registering client ***\n";
	&__isns_register_client(@_);
}

sub __isns_query_objects {

	local($client_config, @extra_args) = @_;
	my @args;

	push(@args, "--query");
	push(@args, @extra_args) if (@extra_args);

	return &run_client($client_config, @args);
}

sub isns_query_objects {

	local($client, @args) = @_;

	&isns_stage("query", "Querying " . join(' ', @args));
	&__isns_query_objects($client, @args);
	&verify_response($__isns_stage_name, $client);
}

sub query_objects {

	print "*** Querying objects ***\n";
	__isns_query_objects(@_);
}

sub isns_query_eid {

	local($client_config, @extra_args) = @_;
	my $logfile;
	my @args;
	local($eid);

	push(@args, "--query-eid");
	push(@args, @extra_args) if (@extra_args);

	&isns_info("*** Querying for EID ***\n");
	$logfile = &run_client($client_config, @args);

	if ($logfile) {
		$eid = `cat $logfile`;
		unless ($eid) {
			&isns_fail("Server reports empty EID");
		}
		chop($eid);
	}

	return $eid;
}

sub __isns_unregister_client {

	local($client_config, @extra_args) = @_;
	my @args;

	push(@args, "--deregister");
	push(@args, @extra_args) if (@extra_args);

	&run_client($client_config, @args);
}

sub isns_unregister_client {

	my $stage = 0;
	my $client;
	my $server;
	my $eid;

	if ($_[0] =~ m/^\d/o) {
		&isns_stage(shift(@_), "Unregister client");
	} else {
		&isns_stage("unregistration", "Unregister client");
	}

	$client = shift(@_);

	unless (@_) {
		$eid = &isns_query_eid($client);
		push(@_, "eid=$eid");
	}

	&__isns_unregister_client($client, @_);

	$server = $__isns_data{$client,"server_config"};
	&verify_db($__isns_stage_name, $server);
}

sub unregister_client {

	&isns_info("*** Unregistering client ***\n");
	&__isns_unregister_client(@_);
}

sub __isns_register_domain {

	local($client_config, @extra_args) = @_;
	my @args;

	push(@args, "--local --dd-register");
	push(@args, @extra_args) if (@extra_args);

	&run_client($client_config, @args);
}

sub isns_register_domain {

	local($client, @args) = @_;
	my $server;

	&isns_stage("dd-registration", "Registering DD " . join(' ', @args));
	&__isns_register_domain($client, @args);

	$server = $__isns_data{$client,"server_config"};
	&isns_verify_db($server);
}

sub register_domain {

	&isns_info("*** Registering DD ***\n");
	&__isns_register_domain(@_);
}

sub __isns_deregister_domain {

	local($client_config, @extra_args) = @_;
	my @args;

	push(@args, "--local --dd-deregister");
	push(@args, @extra_args) if (@extra_args);

	&run_client($client_config, @args);
}

sub isns_deregister_domain {

	local($client, @args) = @_;
	my $server;

	&isns_stage("dd-deregistration", "Deregistering DD (members)" . join(' ', @args));
	&__isns_deregister_domain($client, @args);

	$server = $__isns_data{$client,"server_config"};
	&isns_verify_db($server);
}

sub isns_external_test {

	local($client, @args) = @_;
	my $logfile;
	my $stage;
	my $cmd;

	$logfile = &get_logfile($client);

	$cmd = shift(@args);
	$stage = $cmd;
	$stage =~ s:.*/::o;

	$cmd = "${__isns_bin}/$cmd -c $client " . join(' ', @args);

	&isns_stage($stage, "Running external $cmd " . join(' ', @args));
	unless (&run_command("$cmd >$logfile")) {
		return undef;
	}

	$server = $__isns_data{$client,"server_config"};
	&isns_verify_db($server);
}

sub __isns_prep_test {

	local($name, $duration, @ARGV) = @_;

	GetOptions('verbose+' => \$__isns_verbose,
		   "quiet"    => \$__isns_quiet,
		   "fast"     => \$__isns_quick,
		   "insecure" => \$__isns_insecure);
	$__isns_verbose = 0 if ($__isns_quiet);
	$__isns_security = 0 if ($__isns_insecure);

	if ($__isns_quick && $duration > 15) {
		print "*** Skipping $name (duration ~ $duration seconds) ***\n";
		exit(0);
	}

	print "*** Starting $name ***\n";
	printf "*** This test case will take about %u sec ***\n", $duration
		if ($duration);
	$__isns_test_name = $name;
	$__isns_test_dir = "$__isns_test_base/$name";
	$__isns_test_dump = "$__isns_test_dir/dump";
	$__isns_test_data = "data/$name";

	# Be careful when removing test dir
	system "rm -rf $__isns_test_dir" if ($__isns_test_dir =~ m:/tmp/:o);

	mkdir $__isns_test_base, 0700;
	mkdir $__isns_test_dir, 0700;
	mkdir $__isns_test_dump, 0700;
}

sub test_prep {

	local($name, @args) = @_;

	__isns_prep_test($name, 0, @args);
}

sub isns_prep_slow_test {

	__isns_prep_test(@_);
}

# Sleep for a few seconds, giving the user some dots to keep
# him occupied.
sub isns_idle {

	local($time) = @_;

	if ($__isns_verbose == 0) {
		sleep $time;
		return;
	}

	$| = 1;
	print "Snooze";
	while ($time--) {
		print ".";
		sleep 1;
	}
	print "\n";
	$| = 0;
}

sub main {

	my $server_config;
	my $client_config;

	&test_prep;

	$server_config = &create_server;
	$client_config = &create_client($server_config);
}

#&main;
1;
