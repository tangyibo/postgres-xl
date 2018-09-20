use strict;
use warnings;
use Cwd;
use Config;
use TestLib;
use Test::More tests => 9;

my $dataDirRoot="~/DATA/pgxl/nodes/";
$ENV{'PGXC_CTL_HOME'} = '/tmp/pgxc_ctl';
my $PGXC_CTL_HOME=$ENV{'PGXC_CTL_HOME'};

#delete related dirs for cleanup
system("rm -rf $dataDirRoot");
system("rm -rf $PGXC_CTL_HOME");

my $GTM_HOST = "localhost";
my $COORD1_HOST = "localhost";
my $COORD2_HOST = "localhost";
my $COORD3_HOST = "localhost";
my $COORD1_PORT=30001;
my $COORD2_PORT=30002;
my $COORD3_PORT=30003;
my $DN1_HOST = "localhost";
my $DN2_HOST = "localhost";
my $DN3_HOST = "localhost";
my $TEST_DB = "testdb";
my $DEFAULT_DB = "postgres";

system_or_bail 'pgxc_ctl', 'prepare', 'config', 'empty' ;

system_or_bail 'pgxc_ctl', 'add', 'gtm', 'master', 'gtm', "$GTM_HOST", '20001', "$dataDirRoot/gtm" ;

system_or_bail 'pgxc_ctl', 'add', 'coordinator', 'master', 'coord1', "$COORD1_HOST", '30001', '30011', "$dataDirRoot/coord_master.1", 'none', 'none';

system_or_bail 'pgxc_ctl', 'add', 'datanode', 'master', 'dn1', "$DN1_HOST", '40001', '40011', "$dataDirRoot/dn_master.1", 'none', 'none', 'none' ;

system_or_bail 'pgxc_ctl', 'add', 'datanode', 'master', 'dn2', "$DN2_HOST", '40002', '40012', "$dataDirRoot/dn_master.2", 'none', 'none', 'none' ;

system_or_bail 'pgxc_ctl', 'monitor', 'all' ;

system_or_bail 'psql', '-p', "$COORD1_PORT", "$DEFAULT_DB",'-c', "CREATE DATABASE testdb;";
system_or_bail 'psql', '-p', "$COORD1_PORT", "$TEST_DB",'-c', "create table testtab (a text, b int, c text) distribute by hash(b);";
system_or_bail 'psql', '-p', "$COORD1_PORT", "$TEST_DB",'-c', "alter table testtab drop column a;";
system_or_bail 'psql', '-p', "$COORD1_PORT", "$TEST_DB",'-c', "alter table testtab add column d int;";
system_or_bail 'psql', '-p', "$COORD1_PORT", "$TEST_DB",'-c', "alter table testtab add column a int;";
system_or_bail 'psql', '-p', "$COORD1_PORT", "$TEST_DB",'-c', "insert into testtab values (1, 'foo', 10, 2);";
system_or_bail 'psql', '-p', "$COORD1_PORT", "$TEST_DB",'-c', "insert into testtab values (2, 'foo', 10, 3);";
system_or_bail 'psql', '-p', "$COORD1_PORT", "$TEST_DB",'-c', "insert into testtab values (3, 'foo', 10, 4);";
system_or_bail 'psql', '-p', "$COORD1_PORT", "$TEST_DB",'-c', "insert into testtab values (4, 'foo', 10, 5);";
system_or_bail 'psql', '-p', "$COORD1_PORT", "$TEST_DB",'-c', "insert into testtab values (5, 'foo', 10, 1);";
command_ok(['psql', '-p', "$COORD1_PORT", "$TEST_DB",'-c', "select count(*) from testtab;"], 'select count coord1');
command_ok(['psql', '-p', "$COORD1_PORT", "$TEST_DB",'-c', "select sum(a) from testtab;"], 'select sum(a) coord1');
command_ok(['psql', '-p', "$COORD1_PORT", "$TEST_DB",'-c', "select sum(b) from testtab;"], 'select sum(b) coord1');

system_or_bail 'pgxc_ctl', 'add', 'coordinator', 'master', 'coord2', "$COORD2_HOST", '30002', '30012', "$dataDirRoot/coord_master.2", 'none', 'none';
command_ok(['psql', '-p', "$COORD2_PORT", "$TEST_DB",'-c', "select count(*) from testtab;"], 'select count coord2');
command_ok(['psql', '-p', "$COORD2_PORT", "$TEST_DB",'-c', "select sum(a) from testtab;"], 'select sum(a) coord2');
command_ok(['psql', '-p', "$COORD2_PORT", "$TEST_DB",'-c', "select sum(b) from testtab;"], 'select sum(b) coord2');

system_or_bail 'pgxc_ctl', 'add', 'datanode', 'master', 'dn3', "$DN3_HOST", '40003', '40013', "$dataDirRoot/dn_master.3", 'none', 'none', 'none' ;
system_or_bail 'psql', '-p', "$COORD2_PORT", "$TEST_DB",'-c', "alter table testtab add node (dn3);";

system_or_bail 'pgxc_ctl', 'add', 'coordinator', 'master', 'coord3', "$COORD3_HOST", '30003', '30013', "$dataDirRoot/coord_master.3", 'none', 'none' ;
system_or_bail 'pgxc_ctl', 'monitor', 'all' ;
command_ok(['psql', '-p', "$COORD3_PORT", "$TEST_DB",'-c', "select count(*) from testtab;"], 'select count coord3');
command_ok(['psql', '-p', "$COORD3_PORT", "$TEST_DB",'-c', "select sum(a) from testtab;"], 'select sum(a) coord3');
command_ok(['psql', '-p', "$COORD3_PORT", "$TEST_DB",'-c', "select sum(b) from testtab;"], 'select sum(b) coord3');

#add cleanup
system_or_bail 'pgxc_ctl', 'clean', 'all' ;

#delete related dirs for cleanup
system("rm -rf $dataDirRoot");
system("rm -rf $PGXC_CTL_HOME");
