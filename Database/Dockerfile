# PostgreSQL

# ⭐ Copy files - multistaging it to restrict what final image can see
FROM alpine AS build-copy
WORKDIR /var/lib/postgresql/
COPY Secrets/dbPrivKey.pem /var/lib/postgresql/
COPY Secrets/dbCert.pem /var/lib/postgresql/

COPY Database/createTable.sql /docker-entrypoint-initdb.d/createTable.sql

# ⭐ Actual build
FROM postgres
WORKDIR /var/lib/postgresql/

# Handle keys
COPY --from=build-copy /var/lib/postgresql/ /var/lib/postgresql/
RUN chmod 600 /var/lib/postgresql/dbPrivKey.pem
RUN chown postgres /var/lib/postgresql/dbPrivKey.pem

COPY --from=build-copy /docker-entrypoint-initdb.d/createTable.sql /docker-entrypoint-initdb.d/createTable.sql

# Run the Application
CMD ["postgres", "-c", "ssl=on", "-c", "ssl_cert_file=/var/lib/postgresql/dbCert.pem", "-c", "ssl_key_file=/var/lib/postgresql/dbPrivKey.pem"]