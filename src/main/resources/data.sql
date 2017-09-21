insert into user (id, user_name, password) values (1, 'admin', 'e97c15df9188958552f27736979e9a5d');
insert into user (id, user_name, password) values (2, 'dev', 'e97c15df9188958552f27736979e9a5d');
insert into user (id, user_name, password) values (3, 'test', 'e97c15df9188958552f27736979e9a5d');
insert into role (id, role_name) values (1, 'admin');
insert into role (id, role_name) values (2, 'user');
insert into user_role (id, user_id, role_id) values (1, 1, 1);
insert into user_role (id, user_id, role_id) values (2, 2, 1);
insert into user_role (id, user_id, role_id) values (3, 2, 2);
insert into user_role (id, user_id, role_id) values (4, 3, 2);
