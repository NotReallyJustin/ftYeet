-- The postgresql docker image will execute all startup scripts in /docker-entrypoint-initdb.d/

CREATE TABLE files (
    Name varchar(511),
    PwdHashHash varchar(511),
    BurnOnRead boolean,
    ExpireTime timestamp,
    Url varchar(511),
    CheckSum varchar(511)
)