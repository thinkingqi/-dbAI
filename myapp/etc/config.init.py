#encoding:utf-8
wrong_msg="select '请检查输入语句'"
select_limit=200
export_limit=200
incp_host="192.168.46.105"
public_user="public"
incp_port=6669
incp_user="root"
incp_passwd=""
sqladvisor_switch = 0
sqladvisor = '/usr/sbin/sqladvisor'
pt_tool = 1
pt_tool_path = '/usr/local/bin/'
incept_backup_host = '192.168.46.105'
incept_backup_port = '3306'
incept_backup_user = 'inc_pro'
incept_backup_passwd = 'inc'
path_to_mysqldiff = "/usr/local/bin/mysqldiff"
opsdbpwd='fdad5dba11086da5c725ec9fad164dd9a18bbd36b5e514af586f39d3c54f7b40260e1c8dae3e57ca13a24fb2eef89a72'
opsdbuser='dbadmin'
dbamails=['qihengshan@chehejia.com']
#数据库权限列表
MYSQL_PRIVS = [
    'ALL', 'SELECT', 'UPDATE', 'INSERT', 'DELETE', 'ALTER', 'CREATE', 'INDEX', 'DROP',
    'PROCESS', 'RELOAD', 'REPLICATION CLIENT', 'REPLICATION SLAVE', 'USAGE', 'REFERENCES',
    'CREATE TEMPORARY TABLES', 'SHOW VIEW', 'CREATE ROUTINE', 'ALTER ROUTINE', 'EXECUTE', 'EVENT', 'CREATE VIEW',
    'SHOW DATABASES','FILE','PROCESSES', 'SHUTDOWN', 'SUPER'
]