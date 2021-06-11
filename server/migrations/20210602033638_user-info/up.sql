begin;

alter table slackat.users
    add column name text,
    add column email text,
    add column tz text;

commit;