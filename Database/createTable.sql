-- The postgresql docker image will execute all startup scripts in /docker-entrypoint-initdb.d/

-- CREATE DATABASE main;

-- \c main

CREATE TABLE files (
    UUID UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    PwdHashHash varchar(512),
    BurnOnRead boolean,
    ExpireTime timestamp,
    Url varchar(512),
    CheckSum varchar(512),
    -- URL should be unique
    UNIQUE(Url)
);

CREATE TABLE filesAsymm (
    UUID UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    PubKeyB64 text,
    BurnOnRead boolean,
    ExpireTime timestamp,
    Url varchar(512),
    -- We're only going to need 256 bits/32 bytes for this
    Challenge bytea,
    ChallengeTime timestamp,
    CheckSum varchar(512),
    -- URL should be unique
    UNIQUE(Url)
);