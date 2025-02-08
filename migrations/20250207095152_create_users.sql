-- +goose Up
-- +goose StatementBegin
create table if not exists auth_users (
    id integer primary key,
    email text unique not null,
    password text not null
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
drop table auth_users;
-- +goose StatementEnd
