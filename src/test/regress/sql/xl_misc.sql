
-- try a special column name 
create table xltest_type ("primary" integer, b integer);
insert into xltest_type values(1, 11);
insert into xltest_type values(2, 12);
insert into xltest_type values(3, 13);

select count(*) from xltest_type;
set enable_fast_query_shipping to false;
select count(*) from xltest_type;
select * from xltest_type order by "primary";

drop table xltest_type;


-- repeat with a temp table
set enable_fast_query_shipping to default;
create temp table xltest_type ("primary" integer, b integer);
insert into xltest_type values(1, 11);
insert into xltest_type values(2, 12);
insert into xltest_type values(3, 13);

select count(*) from xltest_type;
set enable_fast_query_shipping to false;
select count(*) from xltest_type;
select * from xltest_type order by "primary";

drop table xltest_type;


-- try a special table name
set enable_fast_query_shipping to default;
create table "XLTEST_type" ("primary" integer, b integer);
-- fail
insert into xltest_type values(1, 11);
-- fail
insert into XLTEST_type values(1, 11);
-- ok
insert into "XLTEST_type" values(1, 11);
insert into "XLTEST_type" values(2, 12);
insert into "XLTEST_type" values(3, 13);

-- fail
select count(*) from XLTEST_type;
-- ok
select count(*) from "XLTEST_type";
select array_agg(c.*) from "XLTEST_type" c where c.primary = 1;

set enable_fast_query_shipping to false;
-- fail
select count(*) from XLTEST_type;
-- ok
select count(*) from "XLTEST_type";

select array_agg(c.*) from "XLTEST_type" c where c.primary = 1;

-- fail
drop table xltest_type;
-- fail
drop table XLTEST_type;
-- fail
drop table "XLTEST_TYPE";
-- ok
drop table "XLTEST_type";

-- try schema qualification for simple schema name
set enable_fast_query_shipping to default;
create schema xltypeschema;
create table xltypeschema."XLTEST_type" ("primary" integer, b integer);
insert into xltypeschema."XLTEST_type" values(1, 11);
insert into xltypeschema."XLTEST_type" values(2, 12);
insert into xltypeschema."XLTEST_type" values(3, 13);

select array_agg(c.*) from "XLTEST_type" c where c.primary = 1;
select array_agg(c.*) from xltypeschema."XLTEST_type" c where c.primary = 1;

drop table xltypeschema."XLTEST_type";

-- try schema qualification for special schema name
create schema "XL.Schema";
create table "XL.Schema"."XLTEST_type" ("primary" integer, b integer);
insert into "XL.Schema"."XLTEST_type" values(1, 11);
insert into "XL.Schema"."XLTEST_type" values(2, 12);
insert into "XL.Schema"."XLTEST_type" values(3, 13);

select array_agg(c.*) from "XL.Schema"."XLTEST_type" c where c.primary = 1;

-- without schema, fail
select array_agg(c.*) from "XLTEST_type" c;
set search_path = "XL.Schema";
-- should work
select array_agg(c.*) from "XLTEST_type" c where c.primary = 1;

drop table "XL.Schema"."XLTEST_type";

