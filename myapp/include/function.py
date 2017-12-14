#!/bin/env python
#-*-coding:utf-8-*-
import MySQLdb,sys,string,time,datetime,uuid,commands,os
from myapp.include.encrypt import prpcrypt
from django.contrib.auth.models import User,Permission,ContentType,Group
from myapp.models import Db_name,Db_account,Db_instance,Oper_log,Login_log,Db_group,Db_privileges
from myapp.form import LoginForm,Captcha
from myapp.etc import config
from mypro import settings


reload(sys)
sys.setdefaultencoding('utf8')
import ConfigParser
#
# def get_item(data_dict,item):
#     try:
#        item_value = data_dict[item]
#        return item_value
#     except:
#        return '-1'
#
# def get_config(group,config_name):
#     config = ConfigParser.ConfigParser()
#     config.readfp(open('./myapp/etc/config.ini','r'))
#     config_value=config.get(group,config_name).strip(' ').strip('\'').strip('\"')
#     return config_value
#
# def filters(data):
#     return data.strip(' ').strip('\n').strip('\br')
#
# host = get_config('settings','host')
# port = get_config('settings','port')
# user = get_config('settings','user')
# passwd = get_config('settings','passwd')
# dbname = get_config('settings','dbname')
# select_limit = int(get_config('settings','select_limit'))
# export_limit = int(get_config('settings','export_limit'))
# wrong_msg = get_config('settings','wrong_msg')
# public_user = get_config('settings','public_user')

# host = config.host
# port = config.port
# user = config.user
# passwd = config.passwd
# dbname = config.dbname

host = settings.DATABASES['default']['HOST']
port = settings.DATABASES['default']['PORT']
user = settings.DATABASES['default']['USER']
passwd = settings.DATABASES['default']['PASSWORD']
dbname = settings.DATABASES['default']['NAME']
select_limit = int(config.select_limit)
export_limit = int(config.export_limit)
wrong_msg = config.wrong_msg
public_user = config.public_user
sqladvisor = config.sqladvisor
advisor_switch = config.sqladvisor_switch
path_mysqldiff = config.path_to_mysqldiff
#
# exceptlist = ["'","`","\""]
#
# def sql_init_filter(sqlfull):
#     tmp = oldp = sql = ''
#     sqllist = []
#     flag = 0
#     sqlfull = sqlfull.replace('\r','\n').strip()
#     try:
#         if sqlfull[-1]!=";":
#             sqlfull = sqlfull + ";"
#     except Exception,e:
#         pass
#     for i in sqlfull.split('\n'):
#         if len(i)>=2:
#             if i[0] == '-' and i[1] == '-' :
#                 continue
#         if len(i)>=1:
#             if i[0] == '#' :
#                 continue
#         if len(i)!=0:
#             tmp = tmp + i + '\n'
#
#     sqlfull = tmp
#     tmp = ''
#     i=0
#     while i<= (0 if len(sqlfull)==0 else len(sqlfull)-1):
#         if sqlfull[i] =='*' and oldp == '/'and flag == 0 :
#             flag = 2
#             sql = sql + sqlfull[i]
#         elif sqlfull[i] == '/' and oldp == '*' and flag == 2:
#             flag = 0
#             sql = sql + sqlfull[i]
#         elif sqlfull[i] == tmp and flag == 1:
#             flag = 0
#             sql = sql + sqlfull[i]
#             tmp=''
#         elif sqlfull[i] in exceptlist and flag == 0 and oldp != "\\":
#             tmp = sqlfull[i]
#             flag = 1
#             sql = sql + sqlfull[i]
#         elif sqlfull[i] == ';' and flag == 0:
#             sql = sql + sqlfull[i]
#             if len(sql) > 1:
#                 sqllist.append(sql)
#             sql = ''
#         # eliminate '#' among the line
#         elif sqlfull[i] == '#' and flag == 0:
#             flag =3
#         elif flag==3:
#             if sqlfull[i] == '\n':
#                 flag=0
#                 sql = sql + sqlfull[i]
#         else:
#             sql = sql + sqlfull[i]
#         oldp = sqlfull[i]
#         i=i+1
#     return sqllist
#
#
# def get_sql_detail(sqllist,flag):
#
#     query_type = ['desc','describe','show','select','explain']
#     dml_type = ['insert', 'update', 'delete', 'create', 'alter','rename', 'drop', 'truncate', 'replace']
#     if flag == 1:
#         list_type = query_type
#     elif flag ==2:
#         list_type = dml_type
#     typelist = []
#     i = 0
#     while i <= (0 if len(sqllist) == 0 else len(sqllist) - 1):
#         try:
#             type = sqllist[i].split()[0].lower()
#             if len(type)> 1:
#                 if type in list_type:
#                     #filter create or drop database,user
#                     if type == 'create' or type == 'drop' or type == 'alter':
#                         if sqllist[i].split()[1].lower() in ['database','user']:
#                             sqllist.pop(i)
#                             #i=i+1
#                             continue
#                     typelist.append(type)
#                     i = i + 1
#                 else:
#                     sqllist.pop(i)
#             else:
#                 sqllist.pop(i)
#         except:
#             i = i + 1
#
#     return sqllist


def mysql_query(sql,user=user,passwd=passwd,host=host,port=int(port),dbname=dbname,limitnum=select_limit):
    try:
        conn=MySQLdb.connect(host=host,user=user,passwd=passwd,port=int(port),connect_timeout=5,charset='utf8')
        conn.select_db(dbname)
        cursor = conn.cursor()
        count=cursor.execute(sql)
        index=cursor.description
        col=[]
        #get column name
        for i in index:
            col.append(i[0])
        #result=cursor.fetchall()
        result=cursor.fetchmany(size=int(limitnum))
        cursor.close()
        conn.close()
        return (result,col)
    except Exception,e:
        return([str(e)],''),['error']
#获取下拉菜单列表
def get_mysql_hostlist(username,tag='tag',search=''):
    dbtype='mysql'
    host_list = []
    if len(search) ==0:
        if (tag=='tag'):
            a = User.objects.get(username=username)
            #如果没有对应role='read'或者role='all'的account账号，则不显示在下拉菜单中
            # for row in a.db_name_set.all().order_by("dbtag"):
            #     if row.db_account_set.all().filter(role__in=['read','all']):
            #         if row.instance.all().filter(role__in=['read','all']).filter(db_type=dbtype):
            #             host_list.append(row.dbtag)
            for row in a.db_name_set.filter(db_account__role__in=['read','all']).filter(
                    instance__role__in=['read','all']).filter(instance__db_type=dbtype).values(
                    'dbtag').distinct().order_by("dbtag"):
                host_list.append(row['dbtag'])
        elif (tag=='log'):
            for row in Db_name.objects.values('dbtag').distinct().order_by("dbtag"):
                host_list.append(row['dbtag'])
        elif (tag=='exec'):
            a = User.objects.get(username=username)
            #如果没有对应role='write'或者role='all'的account账号，则不显示在下拉菜单中
            # for row in a.db_name_set.all().order_by("dbtag"):
            #     if row.db_account_set.all().filter(role__in=['write','all']):
            # #排除只读实例
            #         if row.instance.all().filter(role__in=['write','all']).filter(db_type=dbtype):
            #             host_list.append(row.dbtag)

            for row in a.db_name_set.filter(db_account__role__in=['write', 'all']).filter(
                    instance__role__in=['write', 'all']).filter(instance__db_type=dbtype).values(
                    'dbtag').all().distinct().order_by("dbtag"):
                host_list.append(row['dbtag'])
        elif (tag == 'incept'):
            a = User.objects.get(username=username)
            # for row in a.db_name_set.all().order_by("dbtag"):
            #     #find the account which is admin
            #     if row.db_account_set.all().filter(role='admin'):
            #         if row.instance.all().filter(role__in=['write','all']).filter(db_type=dbtype):
            #         #if row.instance.all().exclude(role='read'):
            #             host_list.append(row.dbtag)
            for row in a.db_name_set.filter(db_account__role='admin').filter(
                    instance__role__in=['write', 'all']).filter(instance__db_type=dbtype).values(
                    'dbtag').all().distinct().order_by("dbtag"):
                host_list.append(row['dbtag'])
        elif (tag == 'meta'):
            # for row in Db_name.objects.all().order_by("dbtag"):
            #     #find the account which is admin
            #     if row.db_account_set.all().filter(role='admin'):
            #         if row.instance.filter(role__in=['write','all','read']).filter(db_type=dbtype):
            #             host_list.append(row.dbtag)
            for row in Db_name.objects.filter(db_account__role='admin').filter(
                    instance__role__in=['write', 'all','read']).filter(instance__db_type=dbtype).values(
                    'dbtag').all().distinct().order_by("dbtag"):
                host_list.append(row['dbtag'])
    elif len(search) > 0:
        if (tag=='tag'):
            a = User.objects.get(username=username)
            #如果没有对应role='read'或者role='all'的account账号，则不显示在下拉菜单中
            # for row in a.db_name_set.filter(dbname__contains=search).order_by("dbtag"):
            #     if row.db_account_set.all().filter(role__in=['read','all']):
            #         if row.instance.all().filter(role__in=['read','all']).filter(db_type=dbtype):
            #             host_list.append(row.dbtag)
            for row in a.db_name_set.filter(dbname__contains=search).filter(db_account__role__in=['read', 'all']).filter(
                    instance__role__in=['read', 'all']).filter(instance__db_type=dbtype).values(
                    'dbtag').distinct().order_by("dbtag"):
                host_list.append(row['dbtag'])
        elif (tag=='log'):
            for row in Db_name.objects.values('dbtag').distinct().order_by("dbtag"):
                host_list.append(row['dbtag'])
        elif (tag=='exec'):
            a = User.objects.get(username=username)
            #如果没有对应role='write'或者role='all'的account账号，则不显示在下拉菜单中
            # for row in a.db_name_set.filter(dbname__contains=search).order_by("dbtag"):
            #     if row.db_account_set.all().filter(role__in=['write','all']):
            # #排除只读实例
            #         if row.instance.all().filter(role__in=['write','all']).filter(db_type=dbtype):
            #             host_list.append(row.dbtag)
            for row in a.db_name_set.filter(dbname__contains=search).filter(db_account__role__in=['write', 'all']).filter(
                    instance__role__in=['write', 'all']).filter(instance__db_type=dbtype).values(
                    'dbtag').all().distinct().order_by("dbtag"):
                host_list.append(row['dbtag'])
        elif (tag == 'incept'):
            a = User.objects.get(username=username)
            # for row in a.db_name_set.filter(dbname__contains=search).order_by("dbtag"):
            #     #find the account which is admin
            #     if row.db_account_set.all().filter(role='admin'):
            #         if row.instance.all().filter(role__in=['write','all']).filter(db_type=dbtype):
            #         #if row.instance.all().exclude(role='read'):
            #             host_list.append(row.dbtag)
            for row in a.db_name_set.filter(dbname__contains=search).filter(db_account__role='admin').filter(
                    instance__role__in=['write', 'all']).filter(instance__db_type=dbtype).values(
                    'dbtag').all().distinct().order_by("dbtag"):
                host_list.append(row['dbtag'])
        elif (tag == 'meta'):
            # for row in Db_name.filter(dbname__contains=search).order_by("dbtag"):
            #     #find the account which is admin
            #     if row.db_account_set.all().filter(role='admin'):
            #         if row.instance.filter(role__in=['write','all','read']).filter(db_type=dbtype):
            #             host_list.append(row.dbtag)
            for row in Db_name.objects.filter(dbname__contains=search).filter(db_account__role='admin').filter(
                    instance__role__in=['write', 'all','read']).filter(instance__db_type=dbtype).values(
                    'dbtag').all().distinct().order_by("dbtag"):
                host_list.append(row['dbtag'])
    return host_list
    # host_list = [dbtag, dbtag]





def get_op_type(methods='get'):
    #all表示所有种类
    op_list=['all','incept','truncate','drop','create','delete','update','replace','insert','select','explain','alter','rename','show']
    if (methods=='get'):
        return op_list

def get_db_privs():

    return config.MYSQL_PRIVS

# 有读分离功能
def get_connection_info(hosttag,request):
    # 确认dbname
    a = Db_name.objects.filter(dbtag=hosttag)[0]
    # a = Db_name.objects.get(dbtag=hosttag)
    tar_dbname = a.dbname
    # 如果instance中有备库role='read'，则选择从备库读取
    try:
        if a.instance.all().filter(role='read')[0]:
            tar_host = a.instance.all().filter(role='read')[0].ip
            tar_port = a.instance.all().filter(role='read')[0].port
    # 如果没有设置或没有role=read，则选择第一个读到的all实例读取
    except Exception, e:
        tar_host = a.instance.filter(role='all')[0].ip
        tar_port = a.instance.filter(role='all')[0].port
        # tar_host = a.instance.all()[0].ip
        # tar_port = a.instance.all()[0].port
    pc = prpcrypt()
    for i in a.db_account_set.all():
        if i.role != 'write' and i.role != 'admin':
            # find the specified account for the user
            if i.account.all().filter(username=request.user.username):
                tar_username = i.user
                tar_passwd = pc.decrypt(i.passwd)
                break
    # not find specified account for the user ,specified the public account to the user

    if not vars().has_key('tar_username'):
        for i in a.db_account_set.all():
            if i.role != 'write' and i.role != 'admin':
                # find the specified account for the user
                if i.account.all().filter(username=public_user):
                    tar_username = i.user
                    tar_passwd = pc.decrypt(i.passwd)
                    break
    return tar_port,tar_passwd,tar_username,tar_host,tar_dbname


def get_advice(hosttag, sql, request):
    if advisor_switch!=0:
        tar_port, tar_passwd, tar_username, tar_host,tar_dbname = get_connection_info(hosttag,request)
        # print tar_port+tar_passwd+tar_username+tar_host
        sql=sql.replace('"','\\"').replace('`', '\`')[:-1]
        cmd = sqladvisor+ ' -u %s -p %s -P %d -h %s -d %s -v 1 -q "%s"' %(tar_username,tar_passwd,int(tar_port),tar_host,tar_dbname,sql)
        # print cmd
        status,result_tmp = commands.getstatusoutput(cmd)
        # print result_tmp
        result_list = result_tmp.split('\n')
        results=''
        for i in result_list:
            try:
                unicode(i, 'utf-8')
                results=results+'\n'+i
            except Exception,e:
                pass

        # results = results.replace('\xc0',' ').replace('\xbf',' ')
        print results
    else:
        results = 'sqladvisor not configured yet.'
    return results

# 查询django
def get_mysql_data(hosttag,sql,useraccount,request,limitnum):
    #确认dbname
    a = Db_name.objects.filter(dbtag=hosttag)[0]
    #a = Db_name.objects.get(dbtag=hosttag)
    tar_dbname = a.dbname
    #如果instance中有备库role='read'，则选择从备库读取
    try:
        if a.instance.all().filter(role='read')[0]:
            tar_host = a.instance.all().filter(role='read')[0].ip
            tar_port = a.instance.all().filter(role='read')[0].port
    #如果没有设置或没有role=read，则选择第一个读到的all实例读取
    except Exception,e:
        tar_host = a.instance.filter(role='all')[0].ip
        tar_port = a.instance.filter(role='all')[0].port
        # tar_host = a.instance.all()[0].ip
        # tar_port = a.instance.all()[0].port
    pc = prpcrypt()
    for i in a.db_account_set.all():
        if i.role!='write' and i.role!='admin':
            # find the specified account for the user
            if i.account.all().filter(username=useraccount):
                tar_username = i.user
                tar_passwd = pc.decrypt(i.passwd)
                break
    #not find specified account for the user ,specified the public account to the user
    if not vars().has_key('tar_username'):
        for i in a.db_account_set.all():
            if i.role != 'write' and i.role != 'admin':
                # find the specified account for the user
                if i.account.all().filter(username=public_user):
                    tar_username = i.user
                    tar_passwd = pc.decrypt(i.passwd)
                    break
    #print tar_port+tar_passwd+tar_username+tar_host
    try:
        if (cmp(sql,wrong_msg)):
            log_mysql_op(useraccount,sql,tar_dbname,hosttag,request)
        results,col = mysql_query(sql,tar_username,tar_passwd,tar_host,tar_port,tar_dbname,limitnum)
    except Exception, e:
        #防止日志库记录失败，返回一个wrong_message
        results,col = ([str(e)],''),['error']
        #results,col = mysql_query(wrong_msg,user,passwd,host,int(port),dbname)
    return results,col,tar_dbname


#检查输入语句,并返回行限制数
def check_mysql_query(sqltext,user,type='select'):
    #根据user确定能够select或者export 的行数
    if (type=='export'):
        try :
            num = User.objects.get(username=user).user_profile.export_limit
        except Exception, e:
            num = export_limit
    elif (type=='select'):
        try :
            num = User.objects.get(username=user).user_profile.select_limit
        except Exception, e:
            num = select_limit
    num=str(num)
    limit = ' limit '+ num

    sqltext = sqltext.strip()
    sqltype = sqltext.split()[0].lower()
    list_type = ['select','show','desc','explain','describe']
    #flag 1位有效 0为list_type中的无效值
    flag=0
    while True:
        sqltext = sqltext.strip()
        lastletter = sqltext[len(sqltext)-1]
        if (not cmp(lastletter,';')):
            sqltext = sqltext[:-1]
        else:
            break
    #判断语句中是否已经存在limit，has_limit 为0时说明原来语句中是有limit的
    try:
        has_limit = cmp(sqltext.split()[-2].lower(),'limit')
    except Exception,e:
        #prevent some input like '1' or 'ss' ...
        return wrong_msg, num

    for i in list_type:
        if (not cmp(i,sqltype)):
            flag=1
            break
    if (flag==1):
        if (sqltype =='select' and has_limit!=0):
            return sqltext+limit,num
        elif (sqltype =='select' and has_limit==0):
            if (int(sqltext.split()[-1])<= int(num) ):
                return sqltext,num
            else:
                tempsql=''
                numlimit=sqltext.split()[-1]
                for i in sqltext.split()[0:-1]:
                    tempsql=tempsql+i+' '
                return tempsql+num,num
        else:
            return sqltext,num
    else:
        return wrong_msg,num

#记录用户所有操作
def log_mysql_op(user,sqltext,mydbname,dbtag,request):
    user = User.objects.get(username=user)
    #lastlogin = user.last_login+datetime.timedelta(hours=8)
    #create_time = datetime.datetime.now()+datetime.timedelta(hours=8)
    lastlogin = user.last_login
    create_time = datetime.datetime.now()
    username = user.username
    sqltype=sqltext.split()[0].lower()
    if sqltype in ['desc','describe']:
        sqltype='show'
    #获取ip地址
    ipaddr = get_client_ip(request)
    log = Oper_log (user=username,sqltext=sqltext,sqltype=sqltype,login_time=lastlogin,create_time=create_time,dbname=mydbname,dbtag=dbtag,ipaddr=ipaddr)
    log.save()
    return 1

def log_mongo_op(sqltext,dbtag,tbname,request):
    user = User.objects.get(username=request.user.username)
    lastlogin = user.last_login
    create_time = datetime.datetime.now()
    username = user.username
    sqltype='select'
    ipaddr = get_client_ip(request)
    log = Oper_log (user=username,sqltext=sqltext,sqltype=sqltype,login_time=lastlogin,create_time=create_time,dbname=tbname,dbtag=dbtag,ipaddr=ipaddr)
    log.save()
    return 1

def log_userlogin(request):
    username = request.user.username
    user = User.objects.get(username=username)
    ipaddr = get_client_ip(request)
    action = 'login'
    create_time = datetime.datetime.now()
    log = Login_log(user=username,ipaddr=ipaddr,action=action,create_time=create_time)
    log.save()

def log_loginfailed(request,username):

    ipaddr = get_client_ip(request)
    action = 'login_failed'
    create_time = datetime.datetime.now()
    log = Login_log(user=username, ipaddr=ipaddr, action=action,create_time=create_time)
    log.save()

def get_log_data(dbtag,optype,begin,end):
    if (optype=='all'):
        #如果结束时间小于开始时间，则以结束时间为准
        if (end > begin):
            log = Oper_log.objects.filter(dbtag=dbtag).filter(create_time__lte=end).filter(create_time__gte=begin).order_by("-create_time")[0:100]
        else:
            log = Oper_log.objects.filter(dbtag=dbtag).filter(create_time__lte=end).order_by("-create_time")[0:100]
    else:
        if (end > begin):
            log = Oper_log.objects.filter(dbtag=dbtag).filter(sqltype=optype).filter(create_time__lte=end).filter(create_time__gte=begin).order_by("-create_time")[0:100]
        else:
            log = Oper_log.objects.filter(dbtag=dbtag).filter(sqltype=optype).filter(create_time__lte=end).order_by("-create_time")[0:100]
    return log

def get_privileges_data(dbtag,optype=None,begin=None,end=None):
    if (optype=='all'):
        #如果结束时间小于开始时间，则以结束时间为准
        if (end > begin):
            log = Db_privileges.objects.filter(grant_dbtag=dbtag).filter(create_time__lte=end).filter(create_time__gte=begin).order_by("-create_time")[0:100]
        else:
            log = Db_privileges.objects.filter(grant_dbtag=dbtag).filter(create_time__lte=end).order_by("-create_time")[0:100]
    else:
        if not optype and not begin and not end:
            log = Db_privileges.objects.filter(grant_dbtag=dbtag).order_by("-create_time")[0:100]
        elif (end > begin):
            log = Db_privileges.objects.filter(grant_dbtag=dbtag).filter(sqltype=optype).filter(create_time__lte=end).filter(create_time__gte=begin).order_by("-create_time")[0:100]
        else:
            log = Db_privileges.objects.filter(grant_dbtag=dbtag).filter(sqltype=optype).filter(create_time__lte=end).order_by("-create_time")[0:100]
    return log

# add
def get_instance_addr(dbtag):
    instance = Db_instance.objects.filter(db_name__dbtag=dbtag)
    dbn = Db_name.objects.filter(dbtag=dbtag)
    addr = dbtag+':'+instance[0].ip+':'+str(instance[0].port)+':'+dbn[0].dbname
    if 'aliyun' in instance[0].ip:
        idc = 1
    elif 'amazon' in instance[0].ip:
        idc = 2
    else:
        idc = 0
    return addr, dbn[0].dbname, idc

from random import Random
pc = prpcrypt()
def random_pwd(randomlength=16): #固定长度16
    pwd = ''    # str初始为空
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    length = len(chars) - 1
    random = Random()
    for i in range(randomlength):    #//循环生成随机字符串
        pwd += chars[random.randint(0, length)]
    return pwd, pc.encrypt(pwd)

def get_decrypt_pwd(pwd):
    return pc.decrypt(pwd)

def get_mypd():
    return pc.decrypt(config.opsdbpwd)

def add_new_priv(dbtool, grant_privs, grant_db, grant_tables, grant_user, grant_ip, grant_user_pwd, idc):
    grant_tbs=[tb.strip() for tb in grant_tables.split(',') if len(tb.strip()) >0]
    grant_ips = [ip.strip() for ip in grant_ip.split(',') if len(ip.strip()) >0]
    if '*' in grant_tbs or '%' in grant_tbs:
        try:
            for ip in grant_ips:
                msg, status = check_user(dbtool, grant_user=grant_user, grant_ip=ip, idc=idc)
                if status == 'ok':
                    sql = "grant {} on {}.* to {}@'"'{}'"' identified by '"'{}'"' ".format(grant_privs, grant_db, grant_user, ip, grant_user_pwd)
                    print("add_new_priv:sql>>>>>: ", sql)
                    try:
                        dbtool.execute(sql)
                    except Exception as e:
                        return str(e), 'notok'
                else:
                    return msg, 'notok'
            return 'Create user and grant privileges SUCC', 'ok'
        except Exception as e:
            return str(e), 'notok'
    else:
        try:
            for tb in grant_tbs:
                if '%' in tb or '*' in tb:
                    tbs = get_tbs(dbtool, grant_db, tb)
                    for t in tbs:
                        t = t.replace('%', '*')
                        for ip in grant_ips:
                            sql = "grant {} on {}.{} to {}@'"'{}'"' identified by '"'{}'"' ".format(grant_privs, grant_db, t, grant_user, ip, grant_user_pwd)
                            try:
                                dbtool.execute(sql)
                            except Exception as e:
                                return str(e), 'notok'
            return 'Create user and grant privileges SUCC', 'ok'
        except Exception as e:
            return str(e), 'notok'

# check user is exists or not
def check_user(dbtool, grant_privs=None, grant_db=None, grant_tables=None, grant_user=None, grant_ip=None, grant_user_pwd=None,idc=None):
    if idc == 1:  # for aliyun
        sql = 'select user,host from mysql.user_view where user={} and host={}'.format(grant_user, grant_ip)
    else:
        sql = 'select user,host from mysql.user where user={} and host={}'.format(grant_user, grant_ip)
    ret = dbtool.query(sql)
    if ret:
        return '{}@"'"{}"'" exists '.format(grant_user, grant_ip), 'notok'
    else:
        return '', 'ok'

# modify priv :button -> confirm_modify
def modify_priv(dbtool, grant_id, grant_privs, grant_db, grant_tables, grant_user, grant_ip, grant_comment, idc):
    pline = Db_privileges.objects.get(id=grant_id)
    grant_tbs = [tb.strip() for tb in grant_tables.split(',') if len(tb.strip()) > 0]
    grant_ips = [ip.strip() for ip in grant_ip.split(',') if len(ip.strip()) > 0]
    grant_privs = [priv.strip() for priv in grant_privs.split(',') if len(priv.strip()) > 0]

    now_tbs = [t.strip() for t in pline.grant_tables.split(',') if len(t.strip()) > 0]
    now_ips = [i.strip() for i in pline.grant_ip.split(',') if len(i.strip()) > 0]
    now_privs = [p.strip() for p in pline.grant_privs.split(',') if len(p.strip()) > 0]

    # add tbs and delete tbs
    plus_tbs = list(set(grant_tbs).intersection(set(now_tbs)))
    minus_tbs = list(set(now_tbs).difference(set(grant_tbs)))

    # add ips and delete ips
    plus_ips = list(set(grant_ips).difference(set(now_ips)))
    minus_ips = list(set(now_ips).difference(set(grant_ips)))

    # add privs and delete privs
    plus_privs = list(set(grant_privs).difference(set(now_privs)))
    minus_privs = list(set(now_privs).difference(set(grant_privs)))

    # last need ips/privs/tbs
    last_ips = list(set(grant_ips).intersection(set(now_ips))) + list(set(grant_ips).difference(set(now_ips)))
    last_privs = list(set(grant_privs).intersection(set(now_privs))) + list(set(grant_privs).difference(set(now_privs)))
    last_tbs = list(set(grant_tbs).intersection(set(now_tbs))) + list(set(grant_tbs).difference(set(now_tbs)))

    for ip in minus_ips:
        sql = 'drop user {}@"'"{}"'" '.format(grant_user, ip)
        print(">>>>>drop user in minus_ips:", sql)
        try:
            dbtool.execute(sql)
        except Exception as e:
            print(">>>drop user error:", e)
            return str(e), 'notok'
    for priv in minus_privs:
        for ip in list(set(now_ips).intersection(set(grant_ips))):
            for tb in now_tbs:
                tb = tb.replace('%', '*')
                sql = 'revoke {} on {}.{} from {}@"'"{}"'" '.format(priv, grant_db, tb, ip)
                print(">>>>revoke priv from user:", sql)
                try:
                    dbtool.execute(sql)
                except Exception as e:
                    print(">>>>revoke privs error: ", e)
                    return str(e), 'notok'
    pwd = pc.decrypt(pline.grant_user_pwd)
    for ip in grant_ips:
        for priv in grant_privs:
            for tb in grant_tbs:
                tb = tb.replace('%', '*')
                sql = 'grant {} on {}.{} to {}@"'"{}"'" identified by "'"{}"'" '.format(priv, grant_db, tb, grant_user, ip, pwd)
                print(">>>> modify button grant sql: ", sql)
                try:
                    dbtool.execute(sql)
                except Exception as e:
                    print("modify button grant error: ", e)
                    return str(e), 'notok'
    try:
        pline.grant_ip = ','.join(grant_ips)
        pline.grant_privs = ','.join(grant_privs)
        pline.grant_tables = ','.join(grant_tables)
        pline.grant_comment = grant_comment
        pline.save()
    except Exception as e:
        print(">>>>pline.save: ", e)
        return str(e), 'notok'
    return 'Modify user and modify privileges SUCC', 'ok'

# for confirm_add_ip button
def confirm_add_ip(dbtool, grant_id, hosttag, grant_user, grant_ip, grant_comment):
    pline = Db_privileges.objects.get(id=grant_id)
    grant_ips = [ip.strip() for ip in grant_ip.split(',') if len(ip.strip()) > 0]
    now_ips = [i.strip() for i in pline.grant_ip.split(',') if len(i.strip()) > 0]
    now_tbs = [t.strip() for t in pline.grant_tables.split(',') if len(t.strip()) > 0]

    plus_ips = list(set(grant_ips).difference(set(now_ips)))
    pwd = pc.decrypt(pline.grant_user_pwd)

    if '%' in now_ips:
        return 'confirm add ip and grant privileges SUCC', 'ok'

    for ip in plus_ips:
        for tb in now_tbs:
            tb = tb.replace('%', '*')
            sql = 'grant {} on {}.{} to {}@"'"{}"'" identified by "'"{}"'" '.format(pline.grant_privs, pline.grant_db, tb, grant_user, ip, pwd)
            print(">>>>confirm_add_ip sql: ", sql)
            try:
                dbtool.execute(sql)
            except Exception as e:
                print(">>>> confirm_add_ip error: ", e)
                return str(e), 'notok'
    # update db_privileges column : grannt_ip
    grant_ips.append(pline.grant_ip)
    total_ip = ','.join(grant_ips)
    pline.grant_ip = total_ip
    pline.grant_comment = grant_comment
    pline.save()

    return 'confirm add ip and grant privileges SUCC', 'ok'

# for confirm_update_pwd button
def confirm_update_pwd(dbtool, grant_id, hosttag, grant_user, grant_ip, update_user_pwd,grant_comment):
    try:
        grant_ips = [ip.strip() for ip in grant_ip.split(',') if len(ip.strip()) > 0]
        for ip in grant_ips:
            sql='set password for {}@"'"{}"'" = password("'"{}"'")'.format(grant_user, ip, update_user_pwd)
            print(">>>> confirm_update_pwd sql:", sql)
            try:
                dbtool.execute(sql)
            except Exception as e:
                print(">>>> confirm_update_pwd error: ", e)
                return str(e), 'notok'
        # -----
        pline = Db_privileges.objects.get(id=grant_id)
        pline.grant_user_pwd = pc.encrypt(update_user_pwd)
        pline.grant_comment = grant_comment
        pline.save()
    except Exception as e:
        return str(e), 'notok'

    return 'confirm update pwd SUCC', 'ok'

# for delete priv
def confirm_delete(dbtool, grant_id, hosttag):
    pline = Db_privileges.objects.get(id=grant_id)
    pline.grant_status = 0
    pline.save()
    # ---
    for ip in pline.grant_ip:
        sql = 'drop user {}@"'"{}"'" '.format(pline.grant_user, ip.strip())
        print(">>>>pline.grant_ip:", pline.grant_ip, ':', sql)
        dbtool.execute(sql)
    return 'delete privileges SUCC', 'ok'


# get table like 'msg%'
def get_tbs(dbtool, grant_db, tb):
    sql = "show tables from {} like {}".format(grant_db, tb)
    ret = dbtool.execute(sql)
    tbs = []
    for item in ret:
       for k, v in item.items():
           tbs.append(v)
    return tbs

# ADD QHS BEFOR get_instance_addr DONE

def check_explain (sqltext):
    sqltext = sqltext.strip()
    sqltype = sqltext.split()[0].lower()
    if (sqltype =='select'):
        sqltext = 'explain extended '+sqltext
        return sqltext
    else:
        return wrong_msg
#
# def my_key(group, request):
#     try:
#         real_ip = request.META['HTTP_X_FORWARDED_FOR']
#         regip = real_ip.split(",")[0]
#     except:
#         try:
#             regip = request.META['REMOTE_ADDR']
#         except:
#             regip = ""
#     form = LoginForm(request.POST)
#     myform = Captcha(request.POST)
#     #验证码正确情况下，错误密码登录次数
#     if form.is_valid() and myform.is_valid():
#         username = form.cleaned_data['username']
#         # password = form.cleaned_data['password']
#
#         return regip+username
#     #验证码错误不计算
#     else:
#         return regip+str(uuid.uuid1())


def get_client_ip(request):
    try:
        real_ip = request.META['HTTP_X_FORWARDED_FOR']
        regip = real_ip.split(",")[0]
    except:
        try:
            regip = request.META['REMOTE_ADDR']
        except:
            regip = ""
    return regip

def check_mysql_exec(sqltext,request,type='dml'):
    # request.user.has_perm('myapp.')
    sqltext = sqltext.strip()
    sqltype = sqltext.split()[0].lower()
    list_type = ['insert','update','delete','create','alter','rename','drop','truncate','replace']
    if (sqltype=='insert'):
        if request.user.has_perm('myapp.can_insert_mysql'):
            return sqltext
        else:
            return "select 'Don\\'t have permission to \"insert\"'"
    elif(sqltype=='update' or sqltype == 'replace'):
        if request.user.has_perm('myapp.can_update_mysql'):
            return sqltext
        else:
            return "select 'Don\\'t have permission to \"update\"'"
    elif(sqltype=='delete'):
        if request.user.has_perm('myapp.can_delete_mysql'):
            return sqltext
        else:
            return "select 'Don\\'t have permission to \"delete\"'"
    elif(sqltype=='truncate'):
        if request.user.has_perm('myapp.can_truncate_mysql'):
            return sqltext
        else:
            return "select 'Don\\'t have permission to \"truncate\"'"
    elif(sqltype=='create'):
        if request.user.has_perm('myapp.can_create_mysql'):
            return sqltext
        else:
            return "select 'Don\\'t have permission to \"create\"'"
    elif(sqltype=='drop'):
        if request.user.has_perm('myapp.can_drop_mysql'):
            return sqltext
        else:
            return "select 'Don\\'t have permission to \"drop\"'"
    elif (sqltype == 'alter' or sqltype == 'rename'):
        if request.user.has_perm('myapp.can_alter_mysql'):
            return sqltext
        else:
            return "select 'Don\\'t have permission to \"alter\"'"
    else:
        return wrong_msg

def run_mysql_exec(hosttag,sql,useraccount,request):
    #确认dbname
    a = Db_name.objects.filter(dbtag=hosttag)[0]
    #a = Db_name.objects.get(dbtag=hosttag)
    tar_dbname = a.dbname
    if (not cmp(sql,wrong_msg)):
        results,col = mysql_query(wrong_msg,user,passwd,host,int(port),dbname)
        return results,col,tar_dbname
    #如果instance中有备库role='write'，则选择从主库读取
    try:
        if a.instance.all().filter(role='write')[0]:
            tar_host = a.instance.all().filter(role='write')[0].ip
            tar_port = a.instance.all().filter(role='write')[0].port
    #如果没有设置或没有role=write，则选择第一个role=all的库读取
    except Exception,e:
        try:
            tar_host = a.instance.all().filter(role='all')[0].ip
            tar_port = a.instance.all().filter(role='all')[0].port
        except Exception,e:
            #没有找到role为all或者write的实例配置
            wrongmsg = "select \"" +str(e).replace('"',"\"")+"\""
            results,col = mysql_query(wrongmsg,user,passwd,host,int(port),dbname)
            return results,col,tar_dbname
    pc = prpcrypt()
    #find the useraccount and passwd for the user
    for i in a.db_account_set.all():
        if i.role != 'read' and i.role != 'admin':
            #find the specified account for the user
            if i.account.all().filter(username=useraccount):
                tar_username = i.user
                tar_passwd = pc.decrypt(i.passwd)
                break
    #not find specified account for the user ,specified the public account to the user
    if not vars().has_key('tar_username'):
        for i in a.db_account_set.all():
            if i.role != 'read' and i.role != 'admin':
                # find the specified account for the user
                if i.account.all().filter(username=public_user):
                    tar_username = i.user
                    tar_passwd = pc.decrypt(i.passwd)
                    break
    try:
        #之前根据check_mysql_exec判断过权限，如果是select则说明没权限，不记录日志
        if (sql.split()[0]!='select'):
            log_mysql_op(useraccount,sql,tar_dbname,hosttag,request)
            results,col = mysql_exec(sql,tar_username,tar_passwd,tar_host,tar_port,tar_dbname)
        else:
            results,col = mysql_query(sql,user,passwd,host,int(port),dbname)
    except Exception, e:
        #防止库连不上,返回一个wrong_message
        results,col = ([str(e)],''),['error']
    return results,col,tar_dbname


# 向后端资源库django写入信息数据
def mysql_exec(sql,user=user,passwd=passwd,host=host,port=int(port),dbname=dbname):
    try:
        conn=MySQLdb.connect(host=host,user=user,passwd=passwd,port=int(port),connect_timeout=5,charset='utf8')
        conn.select_db(dbname)
        curs = conn.cursor()
        result=curs.execute(sql)
        conn.commit()
        curs.close()
        conn.close()
        return (['影响行数: '+str(result)],''),['success']
    except Exception,e:
        if str(e)=='(2014, "Commands out of sync; you can\'t run this command now")':
            return (['只能输入单条sql语句'],''),['error']
        else:
            return([str(e)],''),['error']


def get_pre(dbtag):
    db = Db_name.objects.get(dbtag=dbtag)
    ins = db.instance.all()
    acc = db.account.all()
    acc_list = Db_account.objects.filter(dbname=db)
    gp = db.db_group_set.all()
    return acc_list,ins,acc,gp

def get_user_pre(username,request):
    if len(username)<=30:
        try :
            info = "PRIVILEGES FOR " + username
            dblist = User.objects.get(username=username).db_name_set.all()
        except :
            info = "PLEASE CHECK YOUR INPUT"
            dblist = User.objects.get(username=request.user.username).db_name_set.all()
    else:
        info = "INPUT TOO LONG"
        dblist = User.objects.get(username=request.user.username).db_name_set.all()
    return dblist,info

#used in prequery.html
def get_groupdb(group):
    grouplist = Db_group.objects.filter(groupname=group)
    return grouplist

#used in prequery.html
def get_privileges(username):
    pri = User.objects.get(username=username).user_permissions.all()
    return pri

def get_UserAndGroup():
    user_list = User.objects.exclude(username=public_user).order_by('username')
    group_list = Db_group.objects.all().order_by('groupname')

    # for row in User.objects.all():
    #     user_list.append(row.username)
    return user_list,group_list

def get_user_grouppri(username):
    user = User.objects.get(username=username)
    a = user.db_group_set.all()
    b = user.groups.all()
    return  a,b

def clear_userpri(username):
    user = User.objects.get(username=username)
    for i in Db_name.objects.all():
        i.account.remove(user)
    for i in Db_group.objects.all():
        i.account.remove(user)
    user.user_permissions.clear()
    user.groups.clear()

def set_groupdb(username,li):
    user = User.objects.get(username=username)
    tag_list=[]
    for i in li:
        tmp_gp = Db_group.objects.get(id=i)
        try:
            tmp_gp.account.add(user)
        except Exception,e:
            pass

        for x in tmp_gp.dbname.all():
            tag_list.append(x.dbtag)
            try:
                x.account.add(user)
            except Exception,e:
                pass
    tag_list = list(set(tag_list))
    return tag_list

#create user in pre_set.html
def create_user(username,passwd,mail):
    if len(username)>0 and len(passwd)>0 and len(mail)>0:
        user = User.objects.create_user(username=username,password=passwd,email=mail)
        user.save()
    return user
#delete user in pre_set.html
def delete_user(username):
    user = User.objects.get(username=username)
    user.delete()

#user dbtaglist and user to set user-db relation
def set_user_db(user,dblist):
    setdblist = Db_name.objects.filter(dbtag__in=dblist)
    for i in setdblist:
        try:
            i.account.add(user)
            i.save()
        except Exception,e:
            pass

# a = Permission.objects.filter(codename__istartswith='can')


def set_usergroup(user,group):
    # user.groups.clear()
    grouplist = Group.objects.filter(name__in=group)
    for i in grouplist:
        try:
            user.groups.add(i)
            user.save()
        except Exception,e:
            pass
    # for i in a:
    #     print i.codename

def get_usergp_list():
    # perlist = Permission.objects.filter(codename__istartswith='can')
    grouplist = Group.objects.all().order_by('name')
    return grouplist

def get_diff(dbtag1,tb1,dbtag2,tb2):

    if os.path.isfile(path_mysqldiff):
        tar_host1, tar_port1, tar_username1, tar_passwd1,tar_dbname1 = get_conn_info(dbtag1)
        tar_host2, tar_port2, tar_username2, tar_passwd2,tar_dbname2 = get_conn_info(dbtag2)

        server1 = ' -q --server1={}:{}@{}:{}'.format(tar_username1,tar_passwd1,tar_host1,str(tar_port1))
        server2 = ' --server2={}:{}@{}:{}'.format(tar_username2,tar_passwd2,tar_host2,str(tar_port2))
        option = ' --difftype=sql'
        table = ' {}.{}:{}.{}'.format(tar_dbname1,tb1,tar_dbname2,tb2)
        cmd = path_mysqldiff + server1 + server2 + option + table
        print(">>>>diff_cmd:", cmd)
        output = os.popen(cmd)
        result = output.read()
        # result = commands.getoutput(cmd)
    else :
        result = "mysqldiff not installed"

    return result

def get_conn_info(hosttag):
    a = Db_name.objects.filter(dbtag=hosttag)[0]
    #a = Db_name.objects.get(dbtag=hosttag)
    tar_dbname = a.dbname
    #如果instance中有备库role='read'，则选择从备库读取
    try:
        if a.instance.all().filter(role='read')[0]:
            tar_host = a.instance.all().filter(role='read')[0].ip
            tar_port = a.instance.all().filter(role='read')[0].port
    #如果没有设置或没有role=read，则选择第一个读到的实例读取
    except Exception,e:
        tar_host = a.instance.filter(role__in=['write','all'])[0].ip
        tar_port = a.instance.filter(role__in=['write','all'])[0].port
    pc = prpcrypt()
    for i in a.db_account_set.all():
        if i.role == 'admin':
            tar_username = i.user
            tar_passwd = pc.decrypt(i.passwd)
            break
    return tar_host,tar_port,tar_username,tar_passwd,tar_dbname

def main():
    return 1
if __name__=='__main__':
    main()
