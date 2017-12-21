# dbAI
## 基于`django`、`celery`和`inception`，带权限控制的数据库平台
### 另外还带有一些简单的`saltstack api`和监控功能
## 功能简述如下
+ MySQL 表结构查询功能
+ MySQL 语句查询页面(表级别查询黑名单设置)
+ 支持SQLADVISOR(https://github.com/Meituan-Dianping/SQLAdvisor)
+ MySQL DDL DML语句执行
+ MySQL DDL DML 任务提交(结合inception)
+ Inception 任务管理（包括任务修改、导出、定时执行、终止、结果状态查询、邮件提示、备份查询等）
+ MySQL 实例 部分状态查询
+ MySQL 表相关元数据收集与展示（自增值使用、表大小、重复索引、分区表使用等）
+ Binlog解析功能(https://github.com/danfengcao/binlog2sql)
+ Mongodb简单查询
+ 用户权限分离系统
+ saltstack api（key管理、远程shell、硬件信息）
+ 数据库相关操作日志记录以及查询
+ MySQL数据库健康监控和告警

### 开发环境：
+ django:1.8.14
+ python:2.7.12
+ MySQL和redis实例各一个
### python依赖组件：
+ django-celery 3.1.17
+ celery 3.1.25
+ kombu 3.0.37
+ celery-with-redis 3.0
+ django-simple-captcha
+ MySQL-python
+ pymongo
+ sqlparse
+ uwgsi (正式部署时使用)


### 权限功能简述：
  用户的系统使用权限大致可以分为可以看到的页面，以及能够看到的DB两个维度

  这两个维度的权限都可以通过设置**组**来达到后期快速添加用户的需求

  * 对于前者：

    所有页面都可以根据需要分配给不同权限的用户

  * 对于DB维度的权限：

    一个DB可以配置`role`为`read`和`write`两个ip-port实例，用以区分查询和变更语句执行的实例，（也可以将`role`配置成`all`不进行区分）

    对于数据库账户，一个DB可以配置多个，并分配给不同的用户，用以实现不同用户在同一db下区分权限的功能。（也可以保持默认设置，即分配给`public`用户，不进行区分）

    如果要使用任务管理功能，需要为DB添加一个`role`为**admin**的数据库账号
    。。。待续

### 启动配置
* **config.py**配置文件如下：
``` python

wrong_msg="select '请检查输入语句'"

select_limit=200

export_limit=200

incp_host="10.xx.xx.xx"

public_user="public"

incp_port=6669

incp_user=""

incp_passwd=""

sqladvisor_switch = 1

sqladvisor = '/usr/sbin/sqladvisor'

pt_tool = 1

pt_tool_path = '/usr/bin/'

incept_backup_host = '10.xx.xx.xx'

incept_backup_port = 'xx'

incept_backup_user = 'xx'

incept_backup_passwd = 'xx'

path_to_mysqldiff = "/usr/local/bin/mysqldiff"
```
**说明:**

  `select_limit` 和 `export_limit`为系统默认查询和导出条数限制

  *incp_XX*系列配置文件为`inception`的连接配置
  
  *incept_backup_XX*为配置为inception的备份库，用于查询备份语句

  *sqladvisor_switch*设置为0时不启用`sqladvisor`

  设置`sqladvisor`地址和`sqladvisor_switch`为**1**启用`sqladvisor`

  `setttings.py`中的修改内容主要为`mysql`、`redis`地址，以及邮件服务器相关地址，如果使用`saltapi`功能的话还有一些`salt`相关的信息需要配置
### 启动：
* 初始化表结构： ```python manage.py migrate```
* 创建一个超级用户： ```python manage.py createsuperuser```
* 启动server： 
```
python manage.py runserver 0.0.0.0:8000（启动前建议把settings.py中的debug设置为false） 
```
(上面的启动方式可以自己**测试**时使用，实际使用不要使用`django`自带的`server`启动，因为好像是**单线程**在处理`request`的。。）
  - 建议用`apache`或nginx+uwgsi方式启动，配置文件可以参考`configfile_example`中的
  uwgsi启动方式如：```uwgsi --ini uwgsi.ini```
  nginx配置https时生成key文件示例如下：
```
openssl genrsa -out foobar.key 2048

openssl req -new -key foobar.key -out foobar.csr

openssl x509 -req -days 365 -in foobar.csr -signkey foobar.key -out foobar.crt
```

  **使用`uwgsi`部署时，先 ```python manage.py collectstatic``` 拷下admin之类的静态文件，不然访问`/admin/`页面会找不到样式
  然后以刚刚注册的超级用户登陆网站进行建立普通用户、建库等配置工作**

### 定时任务配置
* 在django库中导入`mon_tb.sql`（文件在`configfile_example`中）
* 启用*celery*的定时任务功能: ```python manage.py celery beat ```
* 启动*celery*: 
```
python manage.py celery worker -E -c 5 --loglevel=info -Q default

python manage.py celery worker -E -c 8 --loglevel=info -Q mysql_monitor
```
* 开启快照监控后，在admin中能看到任务，默认一秒一个快照: ```python manage.py celerycam ```
* 在/admin/中设置定时任务
  * 设置定时扫描task
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/crontab_sche.jpg)
  * 设置元数据收集任务
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/crontab_tbcheck.jpg)


# 页面展示大致如下:
## 1.登录界面
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/login.jpg)
## 2.主页
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/main.jpg)
## 3.表结构查询界面
支持表名模糊搜索
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/meta_query.jpg)
#### 点击表名得到表历史增长信息表（历史信息由定时任务收集）
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/META_DATA1.jpg)
### 3.2查询结果:
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/meta_info.jpg)

## 4.查询界面
### 4.1 MySQL语句查询:
支持**单条**sql的查询和查询结果的导出，导出条数限制默认为`config.py`中配置的值，也可以通过后台`myapp_profile`表对特定用户进行调整
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/mysql_query.jpg)

### 4.2 Mongodb查询界面
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/mongo_query.jpg)
## 5.执行界面
支持**单条**sql语句的执行，用户能够执行的语句类型可以通过权限限制。
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/mysql_exec.jpg)
## 6.任务提交界面

只有审核通过的sql，才能被提交至任务管理页面，提交时可以选择是否执行时备份语句

![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/task_upload.jpg)
## 7.任务管理界面
可以审核、查看、修改、执行、预约任务执行时间，通过调用inception接口来实现

不同用户能够看到的页面按钮可以通过权限控制

任务界面如下：

点击执行后，任务会被发送给`celery`后台异步执行，通过点击状态按钮查看任务执行状态

可以配置邮件在任务生成和任务结束时候发送邮件告知相关人员

可以导出csv格式任务，支持*utf8*和*gb18030*两种导出格式

![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/task_manage1.jpg)
### 7.1任务执行结果示例
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/resul_of_task.jpg)
### 7.2 任务终止
通过pt-osc执行的任务

通过inception调用pt-osc执行的任务可以被终止，但停止后需要到库中人工清理触发器
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/task_stop_ptosc.jpg)
未通过pt-osc执行的任务
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/task_stop.jpg)

### 7.3 任务编辑界面
可以通过权限设置来限制用户是否能够编辑此页面的内容

可以单独变更执行的数据源，以实现同一语句在不同环境执行的需求

变更数据源后，会新生成一个任务，并发送邮件告知
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/task_edit_1.jpg)

## 8.日志查询界面
本平台记录所有用户在mysql_query,mysql_exec以及任务管理页面中执行的语句

这些语句可以通过日志查询页面进行搜索

![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/oper_log.jpg)
## 9. 数据库管理界面
#### 使用页面功能需要配置role为admin的数据库账号

![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/mysql_admin.jpg)
#### 此页面数据由定时任务收集信息得到
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/mysql_admin1.jpg)
#### binlog解析功能（测试）
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/binlog_parse.jpg)
#### binlog解析结果(条数限制在200条)
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/binlog_parse_mail.jpg)


## 10.权限查询页面示例
### 10.1按db查询
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/pre_query_db.jpg)
### 10.2按db组查询
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/pre_query_dbgroup.jpg)
### 10.3按用户账号查询
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/pre_query_user.jpg)
### 10.4按实例查询
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/pre_query_ins.jpg)
## 11.用户账户设置界面
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/user_set.jpg)
## 12.DB快速创建界面
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/fast_dbset.jpg)
## 13.DB详细设置界面
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/db_detailset.jpg)
## 14.用户页面权限设置界面
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/group_set.jpg)
## 15.DB组设置界面
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/dbgroup_set.jpg)

## MySQL监控部分
  源自lepus MySQL部分，做了一定修改
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/mon_set.jpg)
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/mysql_health.jpg)
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/mon_edit.jpg)

## 16.用户密码自助重置页面
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/pass_reset.jpg)
## 17.SALTAPI-WEB页面
### 部分代码参考： https://github.com/yueyongyue/saltshaker
### 17.1 shell命令执行页面
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/SALT_CMD.jpg)
### 17.2 硬件信息查询页面
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/HARDWARE_INFO.jpg)
### 17.3 KEY管理页面
![image](https://github.com/speedocjx/myfile/blob/master/sql-manage-platform/SALT_KEY.jpg)
### 个人编写，精力和水平有限。。有任何疑问和建议联系 changjingxiu1@163.com（qq：710467549）
