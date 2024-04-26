create table user
(
    id                      bigint auto_increment primary key,
    username                varchar(255)         not null,
    password                text                 not null,
    roles                   varchar(255)         not null,
    account_non_expired     tinyint(1) default 1 null,
    account_non_locked      tinyint(1) default 1 null,
    credential_non_expired  tinyint(1) default 1 null,
    enabled                 tinyint(1) default 1 null,
    constraint user_username_idx unique (username)
);