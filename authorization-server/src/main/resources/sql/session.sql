create table spring_session
(
    primary_id            varchar(255) not null,
    session_id            varchar(255) not null,
    creation_time         bigint       not null,
    last_access_time      bigint       not null,
    max_inactive_interval int          not null,
    expiry_time           bigint       not null,
    principal_name        varchar(255) null,
    constraint spring_session_pk primary key (primary_id)
);

create index spring_session_expiry_time_index on spring_session (expiry_time);

create index spring_session_principal_name_index on spring_session (principal_name);

create unique index spring_session_session_id_u_index on spring_session (session_id);


create table spring_session_attributes
(
    session_primary_id varchar(255) not null,
    attribute_name     varchar(255) not null,
    attribute_bytes    blob         not null,
    primary key (session_primary_id, attribute_name),
    constraint spring_session_attributes_spring_session_primary_id_fk
        foreign key (session_primary_id) references spring_session (primary_id) on delete cascade
);
