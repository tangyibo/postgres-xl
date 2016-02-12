CREATE EXTENSION tsm_system_time;

CREATE TABLE test_tablesample (id int, name text) WITH (fillfactor=10); -- force smaller pages so we don't have to load too much data to get multiple pages

-- since it's not repeatable, we expect a Materialize node in these plans:
EXPLAIN (COSTS OFF)
SELECT * FROM
  (VALUES (0),(100000)) v(time),
  LATERAL (SELECT COUNT(*) FROM test_tablesample
           TABLESAMPLE system_time (100000)) ss;

SELECT * FROM
  (VALUES (0),(100000)) v(time),
  LATERAL (SELECT COUNT(*) FROM test_tablesample
           TABLESAMPLE system_time (100000)) ss;

EXPLAIN (COSTS OFF)
SELECT * FROM
  (VALUES (0),(100000)) v(time),
  LATERAL (SELECT COUNT(*) FROM test_tablesample
           TABLESAMPLE system_time (time)) ss;

CREATE VIEW vv AS
  SELECT * FROM test_tablesample TABLESAMPLE system_time (20);

EXPLAIN SELECT id FROM test_tablesample TABLESAMPLE system_time (100) REPEATABLE (10);

DROP EXTENSION tsm_system_time;  -- fail, view depends on extension

DROP VIEW vv;
DROP TABLE test_tablesample;
DROP EXTENSION tsm_system_time;
