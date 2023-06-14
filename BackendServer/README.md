# Azure 
## Install dependencies
```bash
$ sudo apt update
 
$ curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - &&\
$ sudo apt-get install -y nodejs mariadb-server
 
$ sudo apt install npm
$ sudo npm install pm2@latest -g
```

## Setup database
```bash
$ sudo systemctl enable mysql
$ sudo systemctl start mysql
$ sudo mysql 
```
Inside MySQL shell
```mysql
CREATE DATABASE [db_name];
CREATE USER  '[user]'@'%' IDENTIFIED BY '[password]';
GRANT ALL ON *.* to '[user]'@'%' IDENTIFIED BY '[password]' WITH GRANT OPTION;
FLUSH PRIVILEGES;

DROP TABLE IF EXISTS `[db_name]`.`auth`;
DROP TABLE IF EXISTS `[db_name]`.`calls`;
DROP TABLE IF EXISTS `[db_name]`.`contact`;

CREATE TABLE contact (contact_id UUID NOT NULL DEFAULT UUID(), email VARCHAR(64) NOT NULL, last_name VARCHAR(64) NOT NULL, first_name VARCHAR(64) NOT NULL, ip_address VARCHAR(15) NOT NULL, password CHAR(60) NOT NULL, password_expired_at DATETIME NOT NULL, is_active BOOL DEFAULT FALSE, is_locked BOOL DEFAULT FALSE, UNIQUE (email), UNIQUE (contact_id));

CREATE TABLE auth (contact_id UUID NOT NULL, otp CHAR(6), expired_at DATETIME, otp_used BOOL DEFAULT FALSE, failed_attempt INTEGER NOT NULL DEFAULT 0, UNIQUE (contact_id), FOREIGN KEY(contact_id) REFERENCES contact(contact_id) ON DELETE CASCADE);

CREATE TABLE conversation (from_contact UUID NOT NULL, to_contact UUID NOT NULL, created_at DATETIME NOT NULL, status INTEGER NOT NULL, FOREIGN KEY (from_contact) REFERENCES contact(contact_id) ON DELETE CASCADE, FOREIGN KEY (to_contact) REFERENCES contact(contact_id) ON DELETE CASCADE);

CREATE TABLE token (contact_id UUID NOT NULL, token CHAR(32) NOT NULL, created_at DATETIME NOT NULL, expired BOOL DEFAULT FALSE, FOREIGN KEY (contact_id) REFERENCES contact(contact_id));
```

## Install node modules
```bash
$ cd lgvideochat/BackendServe && npm install
```

## Run server
### Source environment
Create a .env file with the following information
```
# Generate secret token inside nodejs shell
# require('crypto').randomBytes(64).toString('hex')

TOKEN_SECRET=
ACCESS_TOKEN_EXPIRED_DURATION=168
ACTIVATION_TOKEN_EXPIRED_DURATION=2

DATABASE_HOST=127.0.0.1
DATABASE_NAME=
DATABASE_USER=
DATABASE_PASSWORD=

MAIL_PORT=587
MAIL_HOST=smtp.ethereal.email
MAIL_USER=chaim48@ethereal.email
MAIL_PASSWORD=eezpJY5ZAR8V9hRQbT

BASE_URL=http://127.0.0.1:3000

```
### Local
```bash
$ node index.js
```
### Using pm2
```bash
$ pm2 start index.js
$ pm2 startup systemd 
```

### Ethereal Mail Service
Go to https://ethereal.email/messages and create a mail account

# Create self-signed certificate
https://www.nginx.com/blog/using-free-ssltls-certificates-from-lets-encrypt-with-nginx/
```bash
openssl genrsa -out lge-backend-key.pem 2048 
openssl req -new -sha256 -key lge-backend-key.pem -out lge-backend-csr.pem 
openssl x509 -req -in lge-backend-csr.pem -signkey lge-backend-key.pem -out lge-backend-cert.pem 

```
