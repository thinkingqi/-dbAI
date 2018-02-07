from __future__ import unicode_literals
from django.contrib.auth.models import User
from django.db import models

read_write = (
    ('read', 'read'),
    ('write', 'write'),
    ('all','all'),
    ('idle','idle'),
)
read_write_account = (
    ('read', 'read'),
    ('write', 'write'),
    ('all','all'),
    ('admin','admin'),
)
db_type = (
    ('mysql', 'mysql'),
    ('mongodb', 'write'),
)

class Db_instance(models.Model):
    ip = models.CharField(max_length=80)
    port = models.CharField(max_length=10)
    role =  models.CharField(max_length=30,choices=read_write, )
    db_type = models.CharField(max_length=30,default='mysql')
    eip = models.CharField(max_length=80, default='')
    comment = models.CharField(max_length=300, default='')
    def __unicode__(self):
        return u'%s %s %s' % (self.ip, self.role, self.db_type)
    class Meta:
        unique_together = ("ip","port")


# db_name match db_instance then db_instance have role for write or read or read_write
class Db_name (models.Model):
    dbtag = models.CharField(max_length=80,unique=True)
    dbname = models.CharField(max_length=30)
    instance = models.ManyToManyField(Db_instance)
    account = models.ManyToManyField(User)
    def __unicode__(self):
        return u'%s %s' % (self.dbtag, self.dbname)


class Db_account(models.Model):
    user = models.CharField(max_length=30)
    passwd = models.CharField(max_length=255)
    role =  models.CharField(max_length=30,choices=read_write_account,default='all')
    tags = models.CharField(max_length=50,db_index=True)
    dbname = models.ManyToManyField(Db_name)
    account = models.ManyToManyField(User)
    def __unicode__(self):
        return  u'%s %s' % ( self.tags,self.role)

class Db_group(models.Model):
    groupname = models.CharField(max_length=30,unique=True)
    dbname = models.ManyToManyField(Db_name)
    account = models.ManyToManyField(User)
    def __unicode__(self):
        return self.groupname

class Oper_log(models.Model):
    user = models.CharField(max_length=35)
    ipaddr = models.CharField(max_length=35)
    dbtag = models.CharField(max_length=35)
    dbname = models.CharField(max_length=40)
    sqltext = models.TextField()
    sqltype = models.CharField(max_length=20)
    create_time = models.DateTimeField(db_index=True)
    login_time = models.DateTimeField()
    def __unicode__(self):
        return self.dbtag
    class Meta:
        index_together = [["dbtag","sqltype", "create_time"],]

class Login_log(models.Model):
    user = models.CharField(max_length=35)
    ipaddr = models.CharField(max_length=35)
    action = models.CharField(max_length=20)
    create_time = models.DateTimeField(db_index=True)

# class Task_scheduler(models.Model):
#     task = models.OneToOneField(Task)
#     appoint_time = models.DateTimeField(db_index=True)
#     def __unicode__(self):
#         return  self.task.id


class User_profile(models.Model):
    user = models.OneToOneField(User)
    select_limit = models.IntegerField(default=200)
    export_limit = models.IntegerField(default=200)
    task_email = models.IntegerField(db_index=True)
    def __unicode__(self):
        return  self.user.username
    class Meta:
        permissions =(('can_mysql_query','can see mysql_query view'),
                      ('can_log_query','can see log_query view'),
                      ('can_see_execview','can see mysql exec view'),
                      ('can_see_inception', 'can see inception view'),
                      ('can_see_metadata', 'can see meta_data view'),
                      ('can_see_mysqladmin', 'can see mysql_admin view'),
                      ('can_export','can export csv'),
                      ('can_insert_mysql','can insert mysql'),
                      ('can_update_mysql','can update mysql'),
                      ('can_delete_mysql','can delete mysql'),
                      ('can_create_mysql','can create mysql'),
                      ('can_drop_mysql','can drop mysql'),
                      ('can_truncate_mysql','can truncate mysql'),
                      ('can_alter_mysql','can alter mysql'),
                      ('can_query_mongo', 'can query mongo'),
                      ('can_see_taskview', 'can see task view'),
                      ('can_admin_task','can admin task'),
                      ('can_delete_task', 'can delete task'),
                      ('can_update_task', 'can update task'),
                      ('can_query_pri', 'can query pri'),
                      ('can_set_pri', 'can set pri'),
                      ('can_oper_saltapi', 'can oper saltapi'),
                      ('can_grant_db', 'can grant db'),
                      ('can_modify_priv', 'can modify priv')
                      )

class Upload(models.Model):
    username = models.CharField(max_length = 40)
    filename = models.FileField(upload_to = 'upload_sql')
    def __unicode__(self):
        return self.username
# Create your models here.
class Task(models.Model):
    user = models.CharField(max_length=35)
    dbtag = models.CharField(max_length=35)
    sqltext = models.TextField()
    create_time = models.DateTimeField(db_index=True)
    update_time = models.DateTimeField()
    status = models.CharField(max_length=20,db_index=True)
    sqlsha =  models.TextField()
    sche_time = models.DateTimeField(db_index=True,default='2199-01-01 00:00:00')
    specification = models.CharField(max_length=100,default='')
    operator = models.CharField(max_length=35, default='')
    backup_status = models.SmallIntegerField(default=1)
    def __unicode__(self):
        return self.dbtag
#backup_status
# o donot  backup
# 1 need  backup
# 2

class Incep_error_log(models.Model):
    myid = models.IntegerField()
    stage = models.CharField(max_length= 20)
    errlevel = models.IntegerField()
    stagestatus = models.CharField(max_length=40)
    errormessage = models.TextField()
    sqltext = models.TextField()
    affectrow = models.IntegerField()
    sequence = models.CharField(max_length=30,db_index=True)
    backup_db = models.CharField(max_length=100)
    execute_time = models.CharField(max_length=20)
    sqlsha = models.CharField(max_length=50)
    create_time = models.DateTimeField(db_index=True)
    finish_time = models.DateTimeField()

class MySQL_monitor(models.Model):
    tag = models.CharField(max_length=80)
    monitor = models.SmallIntegerField(default=1)
    instance = models.OneToOneField(Db_instance)
    # instance = models.ForeignKey(Db_instance)
    check_longsql = models.SmallIntegerField(default=0)
    longsql_time = models.SmallIntegerField(default=1200)
    longsql_autokill = models.SmallIntegerField(default=0)
    check_active = models.SmallIntegerField(default=0)
    active_threshold = models.SmallIntegerField(default=30)
    # account = models.OneToOneField(Db_account)
    account = models.ForeignKey(Db_account)
    check_connections = models.SmallIntegerField(default=0)
    connection_threshold = models.IntegerField(default=1000)
    check_delay = models.SmallIntegerField(default=0)
    delay_threshold = models.IntegerField(default=3600)
    check_slave = models.SmallIntegerField(default=0)
    replchannel = models.CharField(max_length=30,default='0')
    alarm_times = models.SmallIntegerField(default=3)
    alarm_interval = models.SmallIntegerField(default=60)
    mail_to = models.CharField(max_length=255)
    def __unicode__(self):
        return self.tag
    class Meta:
        db_table = 'mysql_monitor'

class Db_privileges(models.Model):
    id=models.AutoField(primary_key=True)
    grant_dbtag=models.CharField(max_length=50, db_index=True)
    grant_user=models.CharField(max_length=30)
    grant_ip=models.CharField(max_length=200)
    grant_privs=models.CharField(max_length=300)
    grant_db=models.CharField(max_length=200)
    grant_tables=models.CharField(max_length=1000)
    grant_user_pwd=models.CharField(max_length=80)
    create_time=models.DateTimeField(auto_now=True, db_index=True)
    modify_time=models.DateTimeField(auto_now_add=True)
    grant_status=models.SmallIntegerField(default=1)  # 1:active 0:inactive
    grant_comment=models.CharField(max_length=200)
    db_name=models.ForeignKey(Db_name, on_delete=models.SET('-1'))
    def __unicode__(self):
        return self.db_name.dbtag

class DB_priv_log(models.Model):
    id=models.AutoField(primary_key=True)
    uname=models.CharField(max_length=30,db_index=True)
    action=models.CharField(max_length=30)
    create_time=models.DateTimeField(auto_now=True, db_index=True)
    fkid=models.ForeignKey(Db_privileges, on_delete=models.SET('-1'))
    priv_status=models.CharField(max_length=20, default='online')
    def __unicode__(self):
        return self.fkid.id, self.fkid.grant_dbtag

class Db_user_pwd(models.Model):
    id=models.AutoField(primary_key=True)
    user = models.OneToOneField(User)
    pwd=models.CharField(max_length=30)
    def __unicode__(self):
        #return self.user.username, self.pwd
        return  u'%s %s' % ( self.user.username,self.pwd)