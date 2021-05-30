begin;

create or replace function slackat.truncate_tables()
    returns text as
$func$
declare
    database_name text;
    table_names text;
    stmt text;
begin
    select into database_name current_database();
    if database_name not like 'slackat_test_%' then
        raise notice 'not truncating because database (%) does not appear to be a test database', database_name;
        return '';
    end if;

    select
        into table_names
        string_agg(format('%I.%I', schemaname, tablename), ', ')
    from pg_tables
    where tableowner = 'slackat'
      and schemaname = 'slackat'
      -- don't truncate migrations
      and tablename not like '%migrations%'
      -- don't truncate enum tables
      and tablename not like '%_enum';

    stmt := 'truncate table ' || table_names || ' cascade';
    raise notice 'executing: %', stmt;
    execute stmt;
    return table_names;
end
$func$ language plpgsql;

commit;
