#!/usr/bin/perl
# Originally From:
# https://www.kernel.org/doc/Documentation/kernel-doc-nano-HOWTO.txt
#
# Changes:
#   * Create manpage section 3 instead of 9.
#   * Replace 'Kernel Hackers Manual' to
#       'iSCSI Userspace API - libopeniscsiusr Manual'
#   * Remove LINUX from header.
$man_sec_num = 3;
$title = 'iSCSI Userspace API - libopeniscsiusr Manual';

if ( $#ARGV < 0 ) {
    die "where do I put the results?\n";
}

mkdir $ARGV[0], 0777;
$state = 0;
while (<STDIN>) {
    if (/^\.TH \"[^\"]*\" 9 \"([^\"]*)\"/) {
        if ( $state == 1 ) { close OUT }
        $state = 1;
        $fn    = "$ARGV[0]/$1.$man_sec_num";
        print STDERR "Creating $fn\n";
        open OUT, ">$fn" or die "can't open $fn: $!\n";

        # Change man page code from 9 to $man_sec_num;
        s/^\.TH (\"[^\"]*\") 9 \"([^\"]*)\"/\.TH $1 $man_sec_num \"$2\"/;
        s/Kernel Hacker's Manual/$title/g;
        s/LINUX//g;

        print OUT $_;
    }
    elsif ( $state != 0 ) {
        print OUT $_;
    }
}

close OUT;
