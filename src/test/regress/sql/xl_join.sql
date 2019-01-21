
CREATE TABLE xl_join_t1 (val1 int, val2 int);
CREATE TABLE xl_join_t2 (val1 int, val2 int);
CREATE TABLE xl_join_t3 (val1 int, val2 int);
CREATE TABLE xl_join_t4 (val1 int, val2 int) DISTRIBUTE BY REPLICATION;
CREATE TABLE xl_join_t5 (val1 int, val2 int) DISTRIBUTE BY REPLICATION;

INSERT INTO xl_join_t1 VALUES (1,10),(2,20);
INSERT INTO xl_join_t2 VALUES (3,30),(4,40);
INSERT INTO xl_join_t3 VALUES (5,50),(6,60);

EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	INNER JOIN xl_join_t2 ON xl_join_t1.val1 = xl_join_t2.val2 
	INNER JOIN xl_join_t3 ON xl_join_t1.val1 = xl_join_t3.val1;

SELECT * FROM xl_join_t1
	INNER JOIN xl_join_t2 ON xl_join_t1.val1 = xl_join_t2.val2 
	INNER JOIN xl_join_t3 ON xl_join_t1.val1 = xl_join_t3.val1;

-- Join on two replicated tables should get shipped, irrespective of the join
-- columns.
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t4
	INNER JOIN xl_join_t5 ON xl_join_t4.val1 = xl_join_t5.val1;
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t4
	INNER JOIN xl_join_t5 ON xl_join_t4.val1 = xl_join_t5.val2;


-- Join on a distributed and one/more replicated tables should get shipped.
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t3
	INNER JOIN xl_join_t5 ON xl_join_t3.val1 = xl_join_t5.val1;
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t3
	INNER JOIN xl_join_t5 ON xl_join_t3.val1 = xl_join_t5.val2
	INNER JOIN xl_join_t4 ON xl_join_t3.val1 = xl_join_t4.val2;

-- Equi-join on distribution column should get shipped
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	INNER JOIN xl_join_t2 ON xl_join_t1.val1 = xl_join_t2.val1;
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	INNER JOIN xl_join_t2 ON xl_join_t1.val1 = xl_join_t2.val1
	INNER JOIN xl_join_t3 ON xl_join_t1.val1 = xl_join_t3.val1;

-- Equi-join on non-distribution column should not get shipped
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	INNER JOIN xl_join_t2 ON xl_join_t1.val2 = xl_join_t2.val2;
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	INNER JOIN xl_join_t2 ON xl_join_t1.val2 = xl_join_t2.val2
	INNER JOIN xl_join_t3 ON xl_join_t1.val1 = xl_join_t3.val1;

-- Equi-join on distribution column and replicated table(s) should get shipped.
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	INNER JOIN xl_join_t2 ON xl_join_t1.val1 = xl_join_t2.val1
	INNER JOIN xl_join_t4 ON xl_join_t1.val1 = xl_join_t4.val1
	INNER JOIN xl_join_t5 ON xl_join_t1.val1 = xl_join_t5.val2;
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	INNER JOIN xl_join_t2 ON xl_join_t1.val1 = xl_join_t2.val1
	INNER JOIN xl_join_t3 ON xl_join_t1.val1 = xl_join_t3.val1
	INNER JOIN xl_join_t4 ON xl_join_t1.val1 = xl_join_t4.val1
	INNER JOIN xl_join_t5 ON xl_join_t1.val1 = xl_join_t5.val2;

EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	INNER JOIN xl_join_t2 ON (xl_join_t1.val1 = xl_join_t2.val1 AND xl_join_t1.val2 = xl_join_t2.val2)
	INNER JOIN xl_join_t3 ON (xl_join_t1.val1 = xl_join_t3.val1 AND xl_join_t1.val2 = xl_join_t3.val2)
	INNER JOIN xl_join_t4 ON xl_join_t1.val1 = xl_join_t4.val1
	INNER JOIN xl_join_t5 ON xl_join_t1.val1 = xl_join_t5.val2;

EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	INNER JOIN xl_join_t2 ON (xl_join_t1.val1 = xl_join_t2.val1 AND xl_join_t1.val2 = xl_join_t2.val2)
	INNER JOIN xl_join_t5 ON (xl_join_t1.val1 = xl_join_t5.val1 AND xl_join_t1.val2 = xl_join_t5.val2)
	INNER JOIN xl_join_t4 ON xl_join_t1.val1 = xl_join_t4.val1
	INNER JOIN xl_join_t3 ON xl_join_t1.val1 = xl_join_t3.val1;

EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	INNER JOIN xl_join_t5 ON (xl_join_t1.val1 = xl_join_t5.val1 AND xl_join_t1.val2 = xl_join_t5.val2)
	INNER JOIN xl_join_t3 ON xl_join_t1.val1 = xl_join_t3.val1;


EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	INNER JOIN xl_join_t2 ON xl_join_t1.val1 = xl_join_t2.val1
	INNER JOIN xl_join_t4 ON xl_join_t1.val1 = xl_join_t4.val1
	INNER JOIN xl_join_t5 ON xl_join_t1.val1 = xl_join_t5.val2
	WHERE xl_join_t1.val1 = 1;

EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	INNER JOIN xl_join_t2 ON xl_join_t1.val1 = xl_join_t2.val1
	INNER JOIN xl_join_t4 ON xl_join_t1.val1 = xl_join_t4.val1
	INNER JOIN xl_join_t5 ON xl_join_t1.val1 = xl_join_t5.val2
	WHERE xl_join_t1.val1 IN (1, 3);


-- LEFT JOIN should get shipped when the right side is replicated
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	LEFT JOIN xl_join_t4 ON xl_join_t1.val1 = xl_join_t4.val1;

-- But not when the left side is replicated
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t4
	LEFT JOIN xl_join_t1 ON xl_join_t1.val1 = xl_join_t4.val1;

-- Similarly RIGHT JOIN is not shipped when the right side is replicated
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	RIGHT JOIN xl_join_t4 ON xl_join_t1.val1 = xl_join_t4.val1;

-- FULL JOIN is shipped only when both sides are replicated or when it's an
-- equi-join on distribution column
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	FULL JOIN xl_join_t2 ON (xl_join_t1.val1 = xl_join_t2.val1);

EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t4
	FULL JOIN xl_join_t5 ON (xl_join_t4.val1 = xl_join_t5.val1);

-- FULL JOIN on a distributed and replicated table is not shipped
EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	FULL JOIN xl_join_t5 ON (xl_join_t1.val1 = xl_join_t5.val1);

EXPLAIN (COSTS OFF)
SELECT * FROM xl_join_t1
	FULL JOIN xl_join_t5 ON (xl_join_t1.val1 = xl_join_t5.val1)
	INNER JOIN xl_join_t2 ON (xl_join_t1.val1 = xl_join_t2.val1);

DROP TABLE xl_join_t1;
DROP TABLE xl_join_t2;
DROP TABLE xl_join_t3;
DROP TABLE xl_join_t4;
DROP TABLE xl_join_t5;
