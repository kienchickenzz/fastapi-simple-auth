-- Users
create user user_migrate with password 'user_migrate';
create user user_write with password 'user_write';
create user user_read with password 'user_read';

-- Groups
create group migrator with user user_migrate;
create group writeaccess with user user_migrate, user_write;
create group readaccess with user user_read;

-- Strict public grants
revoke all on database db from public;
alter default privileges revoke all on functions from public;
revoke create on schema public from public;
grant usage on schema public to public;

-- Migrator grants used for running scripts
grant create, temporary on database db to migrator;
grant create on schema public to migrator;

-- Writer grants
alter default privileges for role user_migrate in schema public grant insert, delete, select, update on tables to writeaccess;
alter default privileges for role user_migrate in schema public grant USAGE, select on SEQUENCES to writeaccess;

-- Reader grants
alter default privileges for role user_migrate in schema public grant select on tables to readaccess;

-- Migrator/service users need to be able to connect
grant connect on database db to writeaccess, readaccess, migrator;
