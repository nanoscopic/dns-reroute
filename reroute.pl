#!/usr/bin/perl -w

use Net::DNS;
use Net::DNS::Nameserver;
use strict;
use XML::Bare qw/xval forcearray/;
#use Data::Dumper;

my %hosthash;
my %iphash;

my ( $ob, $xml ) = new XML::Bare( file => "conf.xml" );
$xml = $xml->{"xml"};
my $entries = forcearray $xml->{"entry"};
for my $entry ( @$entries ) {
	my $ip = xval $entry->{"ip"};
	my $rip = $ip ? reverseip( $ip ) : 0;
	my $cname = xval $entry->{"cname"};
	my $hosts = forcearray( $entry->{"host"} );
	for my $host ( @$hosts ) {
		my $hostname = xval $host;
		$hosthash{ $hostname } = { ip => $ip, cname => $cname };
		if( $ip ) {
			if( !$iphash{ $rip } ) { $iphash{ $rip } = []; }
			print "Reverse $rip -> $hostname\n";
			push @{ $iphash{ $rip } }, $hostname;
		}
	}
}

my $res = Net::DNS::Resolver->new(
	nameservers => [qw(8.8.8.8 8.8.4.4)],
	recurse     => 1,
	debug       => 0,
	searchlist => []
);

sub reverseip {
	my $ip = shift;
	my @arr = split(/\./, $ip );
	@arr = reverse( @arr );
	return join( ".", @arr );
}

sub reply_handler {
	 my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
	 my ($rcode, @ans, @auth, @add);

	 if( $qtype ne "SRV" && $qtype ne "PTR" ) {
	 	 $qname =~ s/\.COMPANYDOMAIN.com$//g;
	 }
	 
	 my %op;
	 my $res2 = "";
	 if( $qtype eq "A" && $hosthash{ $qname } ) {
	 	 
	 	 my $info = $hosthash{ $qname };
	 	 my $ip = $info->{"ip"};
	 	 #print Dumper( $conn );
	 	 if( $conn->{'peerhost'} eq $ip ) {
	 	 	 $ip = "127.0.0.1";
	 	 }
	 	 
	 	 if( $ip ) {
	 	 	 my ($ttl, $rdata) = ( 3600, $ip );
			 push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
			 $rcode = "NOERROR";
		 }
		 else {
		 	 my $cname = $info->{"cname"};
		 	 #print "trying cname for $qname -> $cname\n";
		 	 
		 	 my $answer = $res->search($cname);
		 	 if( $answer && $answer->answer ) {
				 push @ans, $answer->answer;
				 $rcode = "NOERROR";
			 }
			 else {
				 $rcode = "NXDOMAIN";
			 }
		 }
		 $op{ "aa" } = 1; # mark the answer as authoritive (by setting the 'aa' flag
	 }
	 elsif( $qtype eq "AAAA" && $hosthash{ $qname } ) {
	 	 $rcode = "NXDOMAIN";
	 }
	 else {
	 	 my $answer = $res->search($qname,$qtype);
	 	 if( $answer && $answer->answer ) {
			 push @ans, $answer->answer;
			 $rcode = "NOERROR";
		 }
		 else {
		 	 if( $answer ) {
		 	 	 #print Dumper( $answer );
		 	 }
		 	 $rcode = "NXDOMAIN";
		 }
		 
		 if( 0 && $qname =~ m/(.+)\.in-addr\.arpa/ && $qtype eq "PTR" ) {
		 	 my $rip = $1;
		 	 print "Reverse attempt for $rip\n";
		 	 if( $iphash{ $rip } ) {
		 	 	 $rcode = "NOERROR";
		 	 	 my $hosts = $iphash{ $rip };
		 	 	 my $ip = reverseip( $rip );
		 	 	 for my $host ( @$hosts ) {
		 	 	 	 print "Answer: $host\n";
		 	 	 	 push @ans, Net::DNS::RR::PTR->new(
		 	 	 	 	 {
		 	 	 	 	 	rdlength => 0,
		 	 	 	 	 	name => $qname, 
		 	 	 	 	 	ptrdname => $host, 
		 	 	 	 	    ttl => 3600,
		 	 	 	 	    class => "IN",
		 	 	 	 	    type => "PTR"
		 	 	 	 	 } );
		 	 	 }
		 	 }
		 }
	 }
	 	 
	 for my $one ( @ans ) {
	 	 if( $one->{"address"} ) { $res2 .= "\%". $one->{"address"}; }
	 	 if( $qtype eq "PTR" ) {
	 	 	 if( $one->{"ptrdname"} ) { $res2 .= "\%". $one->{"ptrdname"}; }
	 	 }
	 	 if( $qtype eq "SRV" ) {
	 	 	 if( $one->{"target"} ) { $res2 .= "\%". $one->{"target"}; }
	 	 	 if( $one->{"port"} ) { $res2 .= ":". $one->{"port"}; }
	 	 }
	 }
	 open LOG, ">>log";
	 print LOG "$qname,$qtype,$conn->{'peerhost'},$rcode,$res2\n";
	 print "$qname,$qtype,$conn->{'peerhost'},$rcode,$res2\n";
	 close LOG;
	 
	 return ($rcode, \@ans, \@auth, \@add, \%op );
}

my $ns = Net::DNS::Nameserver->new(
 	 LocalAddr => $ARGV[0]||"127.0.0.1",
     LocalPort    => 53,
     ReplyHandler => \&reply_handler,
     Verbose      => 0,
) || die "couldn't create nameserver object\n";

$ns->main_loop;