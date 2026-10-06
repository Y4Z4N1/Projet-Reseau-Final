create database if not exists FINDMYIP character set = 'utf8mb4';

use FINDMYIP ;

create table if not exists userInfo (
    nameUser varchar(100) not null , 
    passwordUser varchar(100) not null ,
    role varchar(20) not null default 'user' ,
    primary key (nameUser)
)engine = INNODB ;

INSERT INTO userInfo (nameUser, passwordUser, role) 
VALUES ('firstadmin', '$2b$12$9bKppilobc0wqkG9VnjZ3uHjOqbRNT8C8TCeckF/OodN49peqRl.W', 'admin');
-- Mdp admin : tuconnaispaslecode