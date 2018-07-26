#!/usr/bin/perl -w

use Net::DNS;
use Net::DNS::Nameserver;
use strict;
use XML::Bare qw/forcearray/;
#use Data::Dumper;

my %hosthash;
my %iphash;

my ( $ob, $xml ) = XML::Bare->simple( file => "conf.xml" );
$xml = $xml->{"xml"};

my $bindip = $xml->{'bindip'};
my $allow_ipv6 = $xml->{'allow_ipv6'} ? 1 : 0;

my $entries = forcearray $xml->{"entry"};
for my $entry ( @$entries ) {
  my $ip = $entry->{"ip"};
  my $rip = $ip ? reverseip( $ip ) : 0;
  my $cname = $entry->{"cname"};
  my $hosts = forcearray( $entry->{"host"} );
  for my $hostname ( @$hosts ) {
    $hosthash{ $hostname } = { ip => $ip, cname => $cname };
    if( $ip ) {
      if( !$iphash{ $rip } ) { $iphash{ $rip } = []; }
      print "Reverse $rip -> $hostname\n";
      push @{ $iphash{ $rip } }, $hostname;
    }
  }
}

my @nameservers = qw/8.8.8.8 8.8.4.4/; # Default to Google DNS service
if( $xml->{'nameserver'} ) {
  @nameservers = ();
  for my $ns ( @{ forcearray( $xml->{'nameserver'} ) } ) {
    my $ns_ip = $ns->{'ip'};
    push( @nameservers, $ns_ip );
  }
}

my @searchdomain;
if( $xml->{'search'} ) {
  for my $ns ( @{ forcearray( $xml->{'search'} ) } ) {
    my $dom = $ns->{'domain'};
    push( @searchdomain, $dom );
  }
}

my $res = Net::DNS::Resolver->new(
  nameservers => \@nameservers,
  recurse     => 1,
  debug       => 0,
  searchlist => \@searchdomain
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
    $qname =~ s/\.COMPANYDOMAIN\.COM$//g;
  }
   
  my %op;
  my $res2 = "";
  if( ( $qtype eq "A" || ( $allow_ipv6 && $qtype eq "AAAA" ) ) && $hosthash{ $qname } ) {
    my $info = $hosthash{ $qname };
    my $ip = $info->{"ip"};
    #print Dumper( $conn );
    #if( $conn->{'peerhost'} eq $ip ) {
    #  $ip = "127.0.0.1";
    #}
      
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
  elsif( ( ! $allow_ipv6 ) && ( $qtype eq "AAAA" && $hosthash{ $qname } ) ) {
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
              name     => $qname, 
              ptrdname => $host, 
              ttl      => 3600,
              class    => "IN",
              type     => "PTR"
            }
          );
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
  LocalAddr    => $ARGV[0]||$bindip,
  LocalPort    => 53,
  ReplyHandler => \&reply_handler,
  Verbose      => 0,
) || die "couldn't create nameserver object\n";

$ns->main_loop;