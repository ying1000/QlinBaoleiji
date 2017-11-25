#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use Crypt::CBC;
use MIME::Base64;
use File::Basename;
use File::Copy;

our($mysql_user,$mysql_passwd) = &get_local_mysql_config();
open(our $fd_log, ">./check_mysql.log");

my $mysql_ip = &get_dbaudit_ip();
if($mysql_ip eq "127.0.0.1")
{
    &write_log("dbaudithost ip is 127.0.0.1");
} 
else
{
    if($mysql_ip eq "")
    {
        &write_log("add dbaudithost to /etc/hosts");
        &file_addline_at_end("/etc/hosts", "127.0.0.1\tdbaudithost");
    }
    else 
    {
        my $dbh=DBI->connect("DBI:mysql:host=$mysql_ip;mysql_connect_timeout=5",$mysql_user,$mysql_passwd,{RaiseError=>0, PrintError=>0});
        if(defined $dbh)
        {
            &write_log("connect mysql on $mysql_ip success");
            $dbh->disconnect;
            close $fd_log;
            exit(0);
        }
        else 
        {
            &write_log("connect mysql on $mysql_ip failed, change /etc/hosts, use 127.0.0.1 on dbaudithost");
            &file_substitute_process("/etc/hosts","dbaudithost","127.0.0.1\tdbaudithost");
        }
    }

    &write_log("restart ftp-audit");
    if(system("/opt/freesvr/audit/sbin/manageprocess.pl ftp-audit restart") != 256)
    {
        &write_log("run manageprocess.pl ftp-audit restart error");
        exit(1);
    }
    &write_log("restart ftp-audit finish");
}

close $fd_log;

sub get_dbaudit_ip 
{
    open(my $fd_fr,"</etc/hosts") or die "cannot open /etc/hosts";
    foreach my $line(<$fd_fr>)
    {
        my($ip, $name) = split /\s+/, $line;
        if($name eq "dbaudithost")
        {
            return $ip;
        }
    }
    return ""
}

sub file_substitute_process
{
    my($file,$attr,$new_value) = @_;
    my $dir = dirname $file;
    my $file_name = basename $file;
    my $backup_name = $file_name.".backup";

    unless(-e "$dir/$backup_name")
    {
        copy($file,"$dir/$backup_name");
    }

    open(my $fd_fr,"<$file") or die "cannot open $file";

    my @file_context;
    foreach my $line(<$fd_fr>)
    {
        chomp $line;
        if($line =~ /$attr/i)
        {
            $line = $new_value;
        }

        push @file_context,$line;
    }

    close $fd_fr;

    open(my $fd_fw,">$file");
    foreach my $line(@file_context)
    {
        print $fd_fw $line,"\n";
    }

    close $fd_fw;
}

sub file_addline_at_end
{
    my($file,$new_line) = @_;
    my $new_line_with_one_space = join " ", (split /\s+/, $new_line);

    my $dir = dirname $file;
    my $file_name = basename $file;
    my $backup_name = $file_name.".backup";
    my $found = 0;

    unless(-e "$dir/$backup_name")
    {
        copy($file,"$dir/$backup_name");
    }

    open(my $fd_fr,"<$file") or die "cannot open $file";

    my @file_context;
    foreach my $line(<$fd_fr>)
    {
        chomp $line;
        push @file_context,$line;

        my $line_with_one_space = join " ", (split /\s+/, $line);
        if($new_line_with_one_space eq $line_with_one_space) 
        {
            $found = 1;
        }
    }

    if($found == 0)
    {
        push @file_context,$new_line;
    }

    close $fd_fr;

    open(my $fd_fw,">$file");
    foreach my $line(@file_context)
    {
        print $fd_fw $line,"\n";
    }

    close $fd_fw;
}

sub write_log
{
    my($str) =  @_;

    my $time_now_utc = time;
    my($sec,$min,$hour,$mday,$mon,$year) = (localtime $time_now_utc)[0..5];
    ($sec, $min,$hour,$mday,$mon,$year) = (sprintf("%02d", $sec),sprintf("%02d", $min),sprintf("%02d", $hour),sprintf("%02d", $mday),sprintf("%02d", $mon + 1),$year+1900);
    my $time_now_str = "$year-$mon-$mday $hour:$min:$sec";

    print $fd_log "[$time_now_str] $str\n"
}

sub get_local_mysql_config
{
    my $tmp_mysql_user = "root";
    my $tmp_mysql_passwd = "";
    open(my $fd_fr, "</opt/freesvr/audit/etc/perl.cnf");
    while(my $line = <$fd_fr>)
    {
        $line =~ s/\s//g;
        my($name, $val) = split /:/, $line;
        if($name eq "mysql_user")
        {
            $tmp_mysql_user = $val;
        }
        elsif($name eq "mysql_passwd")
        {
            $tmp_mysql_passwd = $val;
        }
    }

    my $cipher = Crypt::CBC->new( -key => 'freesvr', -cipher => 'Blowfish', -iv => 'freesvr1', -header => 'none');
    $tmp_mysql_passwd = decode_base64($tmp_mysql_passwd);
    $tmp_mysql_passwd  = $cipher->decrypt($tmp_mysql_passwd);
    close $fd_fr;
    return ($tmp_mysql_user, $tmp_mysql_passwd);
}
