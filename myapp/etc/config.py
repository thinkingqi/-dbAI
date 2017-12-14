#encoding:utf-8
wrong_msg="select '请检查输入语句'"
select_limit=200
export_limit=200
incp_host="xxxx"
public_user="public"
incp_port=6669
incp_user="xxxx"
incp_passwd=""
sqladvisor_switch = 0
sqladvisor = '/usr/sbin/sqladvisor'
pt_tool = 1
pt_tool_path = '/usr/local/bin/'
incept_backup_host = 'xxxx'
incept_backup_port = '3306'
incept_backup_user = 'xxxx'
incept_backup_passwd = 'xxxx'
path_to_mysqldiff = "/usr/local/bin/mysqldiff"
opsdbpwd='xxxx'
opsdbuser='xxxx'
dbamails=['xxxxxx']
#数据库权限列表
MYSQL_PRIVS = [
    'ALL', 'SELECT', 'UPDATE', 'INSERT', 'DELETE', 'ALTER', 'CREATE', 'INDEX', 'DROP',
    'PROCESS', 'RELOAD', 'REPLICATION CLIENT', 'REPLICATION SLAVE', 'USAGE', 'REFERENCES',
    'CREATE TEMPORARY TABLES', 'SHOW VIEW', 'CREATE ROUTINE', 'ALTER ROUTINE', 'EXECUTE', 'EVENT', 'CREATE VIEW',
    'SHOW DATABASES','FILE','PROCESSES', 'SHUTDOWN', 'SUPER'
]