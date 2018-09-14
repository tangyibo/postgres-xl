
create schema if not exists xl_srf;
create table xl_srf.allsets(data jsonb);

create table xl_srf.cards
          as
      select jsonb_array_elements(value->'cards') as data
        from xl_srf.allsets, jsonb_each(data);

create index on xl_srf.cards using gin(data jsonb_path_ops);


begin;

create table xl_srf.sets
    as
select key as name, value - 'cards' as data
  from xl_srf.allsets, jsonb_each(data);

drop table xl_srf.cards;

create table xl_srf.cards
    as
  with collection as
  (
     select key as set,
            value->'cards' as data
       from xl_srf.allsets,
            lateral jsonb_each(data)
  )
  select set, jsonb_array_elements(data) as data
    from collection;

commit;

Insert into xl_srf.cards values ('a', '{"a":[["b",{"x":1}],["b",{"x":2}]],"c":3}');
Insert into xl_srf.cards values ('b', '{"a":[["b",{"x":2}],["b",{"x":3}]],"c":4}');
Insert into xl_srf.cards values ('c', '{"a":[["b",{"x":3}],["b",{"x":4}]],"c":5}');


select case jsonb_typeof(booster)
              when 'array'
              then initcap(jsonb_array_elements_text(booster))
              else initcap(booster #>> '{}')
          end
         as rarity,
         count(*)
    from xl_srf.sets,
         jsonb_array_elements(data->'booster') booster
group by rarity
order by count desc;


with booster(rarity_js) as (
  select case jsonb_typeof(booster)
              when 'array'
              then booster
              else jsonb_build_array(booster)
          end
    from xl_srf.sets,
         jsonb_array_elements(data->'booster') as booster
)
  select initcap(rarity) as rarity, count(*)
    from booster,
         jsonb_array_elements_text(rarity_js) as t(rarity)
group by rarity
order by count desc;

drop table xl_srf.cards;
drop table xl_srf.sets;
drop table xl_srf.allsets;
drop schema xl_srf;
