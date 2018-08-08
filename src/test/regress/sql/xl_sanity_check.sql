--
-- sanity check, if all replicated tables are consistent
--
CREATE OR REPLACE FUNCTION validate_replicated_table(oid) RETURNS BOOL AS $$
DECLARE
    nodes   oid[];
    node    oid;
    nodename    text;
    tablename   text;
    curr_rowcount    bigint;
    query       text;
	prev_rowcount	bigint;
	curr_node		integer;
BEGIN
	curr_node = 0;
	-- get the distribution ndoes
    SELECT nodeoids INTO nodes FROM pgxc_class WHERE pcrelid = $1;

	-- for each node, get the count of rows in the table and match that with
	-- count on other nodes. Any mismatch will be reported via a NOTICE and the
	-- we shall return FALSE.
    FOREACH node IN ARRAY nodes LOOP
		-- Construct an EXECUTE DIRECT query to run on the target node
        SELECT node_name INTO nodename FROM pgxc_node WHERE oid = node;
        SELECT relname INTO tablename FROM pg_class WHERE oid = $1;
        query := 'EXECUTE DIRECT ON (' || nodename || ') '' SELECT count(*) FROM ' || tablename || ' ''';

        EXECUTE query INTO curr_rowcount;
		IF curr_node = 0 THEN
			prev_rowcount = curr_rowcount;
		ELSE
			IF prev_rowcount <> curr_rowcount THEN
				RAISE NOTICE 'Consistency check failed for "%". Node "%" has % rows, other nodes have %', tablename, nodename, curr_rowcount, prev_rowcount;
				RETURN FALSE;
			END IF;
		END IF;
		curr_node = curr_node + 1;
    END LOOP;
	RETURN TRUE;
END
$$ LANGUAGE plpgsql;

--
-- check for all replicated tables
--
DO
$$
DECLARE
    tableoids   oid[];
    oneoid      oid;
BEGIN
    SELECT array_agg(pcrelid) INTO tableoids FROM pgxc_class WHERE pclocatortype = 'R';
    FOREACH oneoid IN ARRAY tableoids LOOP
        PERFORM validate_replicated_table(oneoid);
    END LOOP;
END
$$ LANGUAGE plpgsql;
