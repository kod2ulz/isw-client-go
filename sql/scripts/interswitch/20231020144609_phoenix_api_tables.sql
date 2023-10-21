-- +goose Up
-- +goose StatementBegin
create schema if not exists interswitch;

create table interswitch.api_calls
(
    request_id    uuid primary key not null default uuid_generate_v4(),
    remote_ip     varchar(15)      not null,
    method        varchar(10)      not null,
    url           varchar(100)     not null,
    request       jsonb            not null,
    response      jsonb,
    response_code int,
    initiated_at  timestamp        not null default now(),
    completed_at  timestamp
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
drop table interswitch.api_calls;
drop schema interswitch;
-- +goose StatementEnd
