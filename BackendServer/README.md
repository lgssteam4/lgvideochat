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

CREATE TABLE contact (contact_id UUID NOT NULL DEFAULT UUID(), email VARCHAR(64) NOT NULL, last_name VARCHAR(64) NOT NULL, first_name VARCHAR(64) NOT NULL, ip_address VARCHAR(15) NOT NULL, password CHAR(60) NOT NULL, is_active BOOL DEFAULT FALSE, is_locked BOOL DEFAULT FALSE, UNIQUE (email), UNIQUE (contact_id));

CREATE TABLE auth (contact_id UUID NOT NULL, otp CHAR(6), created_at DATETIME, expired BOOL, wrong_pass_attempt INTEGER NOT NULL, wrong_otp_count INTEGER NOT NULL, UNIQUE (contact_id), FOREIGN KEY(contact_id) REFERENCES contact(contact_id) ON DELETE CASCADE);

CREATE TABLE conversation (from_contact UUID NOT NULL, to_contact UUID NOT NULL, created_at DATETIME NOT NULL, status INTEGER NOT NULL, FOREIGN KEY (from_contact) REFERENCES contact(contact_id) NOT NULL, FOREIGN KEY (to_contact) REFERENCES contact(contact_id) ON DELETE CASCADE);

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

SECRET_TOKEN=
TOKEN_EXPIRED_DURATION=
DATABASE_HOST=
DATABASE_USER=
DATABASE_PASSWORD=
DATABASE_NAME=
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

