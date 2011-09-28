#!/usr/bin/perl

use strict;
use warnings;

my $INTERVAL = 600;  # seconds
my $MAX_USERS = 50;

my @logs;
my @max_log;

my $begin_ts;
while(<>){
    $_ = <>;
    next unless m/^(\d+):(\d+):(\d+) </;
    $begin_ts = ($1 * 60 + $2) * 60 + $3;
    push @logs, $_;
    last;
}

while(<>){
    next unless m/^(\d+):(\d+):(\d+) </;
    my $ts = ($1 * 60 + $2) * 60 + $3;
    push @logs, $_;

    while($ts > $begin_ts + $INTERVAL){
        shift @logs;
        $logs[0] =~ m/^(\d+):(\d+):(\d+)/;
        $begin_ts = ($1 * 60 + $2) * 60 + $3;
    }

    @max_log = @logs if @max_log < @logs;
}

my %msg_count;
foreach(@max_log){
    chomp, warn "[$_]\n" if not m/<([^>]+)>/;
    ++$msg_count{$1};
}

my @counts = sort{ $b->[1] <=> $a->[1] }
             map{ [$_, $msg_count{$_} ] }
             keys %msg_count;
my %id_map;
open STAT, ">stat";
for(my $i = 0; $i < $#counts && $i < $MAX_USERS; ++$i){
    $id_map{$counts[$i][0]} = $i + 1;

    print STAT "$counts[$i][1]\n";
}
close STAT;

@logs = ();
foreach(@max_log){
    m/<([^>]+)>/;
    my $id = $1;
    next if not exists $id_map{$id};
    s/<$id>/<$id_map{$id}>/;
    push @logs, $_;
}

print @logs;
