use strict;
use warnings;
use Cwd;
use Config;
use TestLib;
use Test::More tests => 1;

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
my $DN1_PORT=40001;
my $DN2_PORT=40002;
my $DN3_PORT=40003;
my $TEST_DB = "testdb";
my $DEFAULT_DB = "postgres";

system_or_bail 'pgxc_ctl', 'prepare', 'config', 'empty' ;

system_or_bail 'pgxc_ctl', 'add', 'gtm', 'master', 'gtm', "$GTM_HOST", '20001', "$dataDirRoot/gtm" ;

system_or_bail 'pgxc_ctl', 'add', 'coordinator', 'master', 'coord1', "$COORD1_HOST", '30001', '30011', "$dataDirRoot/coord_master.1", 'none', 'none';

system_or_bail 'pgxc_ctl', 'add', 'datanode', 'master', 'dn1', "$DN1_HOST", '40001', '40011', "$dataDirRoot/dn_master.1", 'none', 'none', 'none' ;

system_or_bail 'pgxc_ctl', 'add', 'datanode', 'master', 'dn2', "$DN2_HOST", '40002', '40012', "$dataDirRoot/dn_master.2", 'none', 'none', 'none' ;

system_or_bail 'pgxc_ctl', 'monitor', 'all' ;

# Create a temp directory to keep intermediate files.
system_or_bail 'mkdir', '-p', 'tmp_check/files';

# Run regression test
system("cd ../../../ && PGPORT=30001 make installcheck");

# Now add one more datanode and a coordinator to the cluster
system_or_bail 'pgxc_ctl', 'add', 'coordinator', 'master', 'coord2', "$COORD2_HOST", '30002', '30012', "$dataDirRoot/coord_master.2", 'none', 'none';
system_or_bail 'pgxc_ctl', 'add', 'datanode', 'master', 'dn3', "$DN3_HOST", '40003', '40013', "$dataDirRoot/dn_master.3", 'none', 'none', 'none' ;
system_or_bail 'pgxc_ctl', 'monitor', 'all' ;

# Take pg_dump from each node for various comparisons later
system("pg_dump -h $COORD1_HOST --include-nodes -p $COORD1_PORT regression > tmp_check/files/coord1.dump.sql");
system("pg_dump -h $COORD2_HOST --include-nodes -p $COORD2_PORT regression > tmp_check/files/coord2.dump.sql");
system("pg_dump -h $DN1_HOST --include-nodes -p $DN2_PORT regression > tmp_check/files/dn1.dump.sql");
system("pg_dump -h $DN2_HOST --include-nodes -p $DN2_PORT regression > tmp_check/files/dn2.dump.sql");
system("pg_dump -h $DN3_HOST --include-nodes -p $DN3_PORT regression > tmp_check/files/dn3.dump.sql");

# Create a bunch of test databases to restore the dump
system_or_bail 'psql', '-p', "$COORD1_PORT", '-h', "$COORD1_HOST", '-c', "create database coord1_restore", 'postgres';
system_or_bail 'psql', '-p', "$COORD1_PORT", '-h', "$COORD1_HOST", '-c', "create database coord2_restore", 'postgres';
system_or_bail 'psql', '-p', "$COORD1_PORT", '-h', "$COORD1_HOST", '-c', "create database dn1_restore", 'postgres';
system_or_bail 'psql', '-p', "$COORD1_PORT", '-h', "$COORD1_HOST", '-c', "create database dn2_restore", 'postgres';

# Restore the dumps obtained from the old and the new coordinator into two
# separate databases
system_or_bail 'psql', '-p', "$COORD1_PORT", '-h', "$COORD1_HOST", '-f', "tmp_check/files/coord1.dump.sql", 'coord1_restore';
system_or_bail 'psql', '-p', "$COORD1_PORT", '-h', "$COORD1_HOST", '-f', "tmp_check/files/coord2.dump.sql", 'coord2_restore';

# !!TODO We can now take additional dumps from the new databases for a much
# saner comparison. 
# system("pg_dump -h $COORD1_HOST --include-nodes -p $COORD1_PORT coord1_restore > tmp_check/files/coord1_postretore.dump.sql");
# system("pg_dump -h $COORD1_HOST --include-nodes -p $COORD1_PORT coord2_restore > tmp_check/files/coord2_postretore.dump.sql");

# Some sanity checks now
system("psql -h $COORD1_HOST -p $COORD1_PORT -f 't/041_sanity.sql' coord1_restore > tmp_check/files/sanityop1");
system("psql -h $COORD1_HOST -p $COORD1_PORT -f 't/041_sanity.sql' coord2_restore > tmp_check/files/sanityop2");
command_ok (['diff', 'tmp_check/files/sanityop1', 'tmp_check/files/sanityop2']);

#add cleanup
system_or_bail 'pgxc_ctl', 'clean', 'all' ;

#delete related dirs for cleanup
system("rm -rf $dataDirRoot");
system("rm -rf $PGXC_CTL_HOME");
system("rm -rf tmp_check/files");
