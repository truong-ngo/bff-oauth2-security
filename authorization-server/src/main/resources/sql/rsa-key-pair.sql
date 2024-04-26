create table rsa_key_pairs
(
    id varchar(1000) not null primary key,
    private_key text not null,
    public_key text not null,
    created date not null,
    unique (id, created)
) DEFAULT CHARSET = utf8 COLLATE = utf8_unicode_ci