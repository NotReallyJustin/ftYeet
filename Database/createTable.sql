-- The postgresql docker image will execute all startup scripts in /docker-entrypoint-initdb.d/

-- CREATE DATABASE main;

-- \c main

CREATE TABLE files (
    Name varchar(512),
    PwdHashHash varchar(512),
    BurnOnRead boolean,
    ExpireTime timestamp,
    Url varchar(512),
    CheckSum varchar(512)
);

CREATE TABLE filesAsymm (
    Name varchar(512),
    PubKeyB64 text,
    BurnOnRead boolean,
    ExpireTime timestamp,
    Url varchar(512),
    -- We're only going to need 126 bits/16 bytes for this
    Challenge bytea,
    ChallengeTime timestamp,
    CheckSum varchar(512)
);