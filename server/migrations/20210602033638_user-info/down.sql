begin;

alter table slackat.users
    drop column tz,
    drop column email,
    drop column name;

commit;