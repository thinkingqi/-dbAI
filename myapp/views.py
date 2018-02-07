import sys,json,os,datetime,csv,time
from django.contrib import admin
from django.template.context import RequestContext
# from ratelimit.decorators import ratelimit,is_ratelimited
from django.shortcuts import render,render_to_response
from django.contrib import auth
from form import AddForm,LoginForm,Logquery,Uploadform,Captcha,Taskquery,Taskscheduler,Dbgroupform
from captcha.fields import CaptchaField,CaptchaStore
from captcha.helpers import captcha_image_url
from django.http import HttpResponse,HttpResponseRedirect,StreamingHttpResponse,JsonResponse
from django.contrib.auth.decorators import login_required,permission_required
from django.contrib.auth.models import User,Permission,ContentType,Group
from myapp.include import function as func,inception as incept,chart,pri,meta,sqlfilter
from myapp.models import Db_group,Db_name,Db_account,Db_instance,Upload,Task,MySQL_monitor,Db_privileges,DB_priv_log,Db_user_pwd
from myapp.tasks import task_run,sendmail_task,parse_binlog,parse_binlogfirst
from blacklist import blFunction as bc
from myapp.include.mylib import DBTool
from myapp.etc.config import opsdbuser
from myapp.include.scheduled import get_dupreport
# for login
import urllib2, cookielib
from etc import config


from django.core.files import File
#path='./myapp/include'
#sys.path.insert(0,path)
#import function as func
# Create your views here.
'''
class CJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime("%Y-%m-%d")
        else:
            return json.JSONEncoder.default(self, obj)
'''

@login_required(login_url='/accounts/login/')
def index(request):
    data,col = chart.get_main_chart()
    taskdata,taskcol = chart.get_task_chart()
    bingtu = chart.get_task_bingtu()
    inc_data,inc_col = chart.get_inc_usedrate()

    # print json.dumps(bingtu)
    return render(request, 'include/base.html',{'inc_data':json.dumps(inc_data),'inc_col':json.dumps(inc_col),'bingtu':json.dumps(bingtu),'data':json.dumps(data),'col':json.dumps(col),'taskdata':json.dumps(taskdata),'taskcol':json.dumps(taskcol)})

'''
@login_required(login_url='/accounts/login/')
def logout(request):
    auth.logout(request)
    response = HttpResponseRedirect("https://boss.dev.chehejia.com/?serviceId=db")
    response.delete_cookie('CHEHEJIASESSIONID', path='/', domain='.chehejia.com')
    try:
        response.delete_cookie('myfavword')
    except Exception,e:
        pass
    return response

'''
@login_required(login_url='/accounts/login/')
def logout(request):
    auth.logout(request)
    response = HttpResponseRedirect("/accounts/login/")
    try:
        response.delete_cookie('myfavword')
    except Exception,e:
        pass
    return response


@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_log_query', login_url='/')
def log_query(request):
    #show every dbtags
    #obj_list = func.get_mysql_hostlist(request.user.username,'log')
    #show dbtags permitted to the user
    obj_list = func.get_mysql_hostlist(request.user.username,'log')
    optype_list = func.get_op_type()
    if request.method == 'POST' :
        form = Logquery(request.POST)
        if form.is_valid():
            begintime = form.cleaned_data['begin']
            endtime = form.cleaned_data['end']
            hosttag = request.POST['hosttag']
            optype = request.POST['optype']
            data = func.get_log_data(hosttag,optype,begintime,endtime)

            return render(request,'log_query.html',{'form': form,'objlist':obj_list,'optypelist':optype_list,'datalist':data,'choosed_host':hosttag})
        else:
            print "not valid"
            return render(request,'log_query.html',{'form': form,'objlist':obj_list,'optypelist':optype_list})
    else:
        form = Logquery()
        return render(request, 'log_query.html', {'form': form,'objlist':obj_list,'optypelist':optype_list})


@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_mysql_query', login_url='/')
def mysql_query(request):
    #print request.user.username
    # print request.user.has_perm('myapp.can_mysql_query')
    try:
        favword = request.COOKIES['myfavword']  # get cookie_data: "myfavword=dfsfd;path=/;expires=Mon, 27 Nov 2017 05:10:16 GMT"
    except Exception,e:
        pass
    objlist = func.get_mysql_hostlist(request.user.username)
    if request.method == 'POST':
        form = AddForm(request.POST)
        # request.session['myfavword'] = request.POST['favword']
        choosed_host = request.POST['cx']

        if not User.objects.get(username=request.user.username).db_name_set.filter(dbtag=choosed_host)[:1]:
            return HttpResponseRedirect("/")

        if request.POST.has_key('searchdb'):
            db_se = request.POST['searchdbname']
            objlist_tmp = func.get_mysql_hostlist(request.user.username, 'tag', db_se)
            # incase not found any db
            if len(objlist_tmp) > 0:
                objlist = objlist_tmp

        if form.is_valid():
            a = form.cleaned_data['a']
            # get first valid statement
            try:
                #print func.sql_init_filter(a)
                a = sqlfilter.get_sql_detail(sqlfilter.sql_init_filter(a), 1)[0]
            except Exception, e:
                a='wrong'
                pass
            try:
                #show explain
                if request.POST.has_key('explain'):
                    a = func.check_explain (a)
                    (data_list,collist,dbname) = func.get_mysql_data(choosed_host,a,request.user.username,request,100)
                    return render(request, 'mysql_query.html', locals())
                    # return render(request,'mysql_query.html',{'form': form,'objlist':objlist,'data_list':data_list,'collist':collist,'choosed_host':choosed_host,'dbname':dbname})
                    #export csv
                elif request.POST.has_key('export') and request.user.has_perm('myapp.can_export') :
                    # check if table in black list and if user has permit to query

                    inBlackList, blacktb = bc.Sqlparse(a).check_query_table(choosed_host,request.user.username)
                    if inBlackList:
                        return render(request, 'mysql_query.html', locals())

                    a,numlimit = func.check_mysql_query(a,request.user.username,'export')
                    (data_list,collist,dbname) = func.get_mysql_data(choosed_host,a,request.user.username,request,numlimit)
                    pseudo_buffer = Echo()
                    writer = csv.writer(pseudo_buffer)
                    #csvdata =  (collist,'')+data_mysql
                    i=0
                    results_long = len(data_list)
                    results_list = [None] * results_long
                    for i in range(results_long):
                        results_list[i] = list(data_list[i])
                    results_list.insert(0,collist)
                    a = u'zhongwen'
                    ul= 1234567L
                    for result in results_list:
                        i=0
                        for item in result:
                            if type(item) == type(a):
                                try:
                                    result[i] = item.encode('gb18030')
                                except Exception,e:
                                    result[i] = item.replace(u'\xa0', u' ').encode('gb18030')
                            elif type(item)==type(ul):
                                try:
                                    result[i] = str(item) + "\t"
                                except Exception,e:
                                    pass
                            i = i + 1
                    response = StreamingHttpResponse((writer.writerow(row) for row in results_list),content_type="text/csv")
                    response['Content-Disposition'] = 'attachment; filename="export.csv"'
                    return response
                elif request.POST.has_key('query'):
                    #check if table in black list and if user has permit to query
                    inBlackList,blacktb = bc.Sqlparse(a).check_query_table(choosed_host,request.user.username)
                    if inBlackList:
                        return render(request, 'mysql_query.html', locals())
                    #get nomal query
                    a,numlimit = func.check_mysql_query(a,request.user.username)
                    (data_list,collist,dbname) = func.get_mysql_data(choosed_host,a,request.user.username,request,numlimit)
                    # donot show wrong message sql
                    if a == func.wrong_msg:
                        del a
                    # print choosed_host
                    return render(request, 'mysql_query.html', locals())
                elif request.POST.has_key('sqladvice'):

                    advice = func.get_advice(choosed_host, a, request)
                    return render(request, 'mysql_query.html', locals())

                return render(request, 'mysql_query.html', locals())

            except Exception,e:
                print e
                return render(request, 'mysql_query.html', locals())
                # return render(request, 'mysql_query.html', {'form': form, 'objlist': objlist})
        else:
            return render(request, 'mysql_query.html', locals())
            # return render(request, 'mysql_query.html', {'form': form,'objlist':objlist})
    else:
        form = AddForm()
        #
        # try:
        #     favword = request.session['myfavword']
        # except Exception,e:
        #     pass

        return render(request, 'mysql_query.html', locals())
        # return render(request, 'mysql_query.html', {'form': form,'objlist':objlist})



# def mysql_query(request):
#     #print request.user.username
#     # print request.user.has_perm('myapp.can_mysql_query')
#     objlist = func.get_mysql_hostlist(request.user.username)
#     if request.method == 'POST':
#         form = AddForm(request.POST)
#         if form.is_valid():
#             a = form.cleaned_data['a']
#             choosed_host = request.POST['cx']
#             try:
#                 #show explain
#                 if request.POST.has_key('explain'):
#                     a = func.check_explain (a)
#                     (data_list,collist,dbname) = func.get_mysql_data(choosed_host,a,request.user.username,request,100)
#                     return render(request, 'mysql_query.html', locals())
#                     # return render(request,'mysql_query.html',{'form': form,'objlist':objlist,'data_list':data_list,'collist':collist,'choosed_host':choosed_host,'dbname':dbname})
#                     #export csv
#                 elif request.POST.has_key('export'):
#                     a,numlimit = func.check_mysql_query(a,request.user.username,'export')
#                     (data_list,collist,dbname) = func.get_mysql_data(choosed_host,a,request.user.username,request,numlimit)
#                     pseudo_buffer = Echo()
#                     writer = csv.writer(pseudo_buffer)
#                     #csvdata =  (collist,'')+data_mysql
#                     i=0
#                     results_long = len(data_list)
#                     results_list = [None] * results_long
#                     for i in range(results_long):
#                         results_list[i] = list(data_list[i])
#                     results_list.insert(0,collist)
#                     a = u'zhongwen'
#                     for result in results_list:
#                         i=0
#                         for item in result:
#                             if type(item) == type(a):
#                                 result[i] = item.encode('gb2312')
#                             i = i + 1
#                     response = StreamingHttpResponse((writer.writerow(row) for row in results_list),content_type="text/csv")
#                     response['Content-Disposition'] = 'attachment; filename="export.csv"'
#                     return response
#                 elif request.POST.has_key('query'):
#                 #get nomal query
#                     a,numlimit = func.check_mysql_query(a,request.user.username)
#                     # print type(a)
#                     # print a
#                     (data_list,collist,dbname) = func.get_mysql_data(choosed_host,a,request.user.username,request,numlimit)
#                     return render(request, 'mysql_query.html', locals())
#
#                     # return render(request,'mysql_query.html',{'form': form,'objlist':objlist,'data_list':data_list,'collist':collist,'choosed_host':choosed_host,'dbname':dbname})
#             except Exception,e:
#                 print e
#                 return render(request, 'mysql_query.html', locals())
#
#                 # return render(request, 'mysql_query.html', {'form': form, 'objlist': objlist})
#         else:
#             return render(request, 'mysql_query.html', locals())
#
#             # return render(request, 'mysql_query.html', {'form': form,'objlist':objlist})
#     else:
#         form = AddForm()
#         return render(request, 'mysql_query.html', locals())
#
#         # return render(request, 'mysql_query.html', {'form': form,'objlist':objlist})




class Echo(object):
    """An object that implements just the write method of the file-like interface.
    """
    def write(self, value):
        """Write the value by returning it, instead of storing in a buffer."""
        return value
'''
def some_streaming_csv_view(request):
    """A view that streams a large CSV file."""
    # Generate a sequence of rows. The range is based on the maximum number of
    # rows that can be handled by a single sheet in most spreadsheet
    # applications.
    data = (["Row {}".format(idx), str(idx)] for idx in range(65536))
    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer)
    response = StreamingHttpResponse((writer.writerow(row) for row in data),
                                     content_type="text/csv")
    response['Content-Disposition'] = 'attachment; filename="test.csv"'
    return response
'''



@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_see_execview', login_url='/')
def mysql_exec(request):
    try:
        favword = request.COOKIES['myfavword']
    except Exception,e:
        pass
    #print request.user.username
    objlist = func.get_mysql_hostlist(request.user.username,'exec')
    if request.method == 'POST':
        form = AddForm(request.POST)
        choosed_host = request.POST['cx']
        if not User.objects.get(username=request.user.username).db_name_set.filter(dbtag=choosed_host)[:1]:
            return HttpResponseRedirect("/")
        if request.POST.has_key('searchdb'):
            db_se = request.POST['searchdbname']
            objlist_tmp = func.get_mysql_hostlist(request.user.username, 'exec', db_se)
            # incase not found any db
            if len(objlist_tmp) > 0:
                objlist = objlist_tmp

        if form.is_valid():
            a = form.cleaned_data['a']
            #try to get the first valid sql
            try:
                a = sqlfilter.get_sql_detail(sqlfilter.sql_init_filter(a), 2)[0]
                # form = AddForm(initial={'a': a})
            except Exception,e:
                # a ='wrong'
                a = "Support SQL Type: 'insert', 'update', 'delete', 'create', 'alter','rename', 'drop', 'truncate', 'replace'"
            sql = a
            a = func.check_mysql_exec(a,request)
            #print request.POST
            if request.POST.has_key('commit'):
                (data_mysql,collist,dbname) = func.run_mysql_exec(choosed_host,a,request.user.username,request)
                print("mysql_exec:exec", data_mysql,'||', collist, '|', dbname)
            elif request.POST.has_key('check'):
                data_mysql,collist,dbname = incept.inception_check(choosed_host,a)

            # return render(request,'mysql_exec.html',{'form': form,'objlist':objlist,'data_mysql':data_mysql,'collist':collist,'choosed_host':choosed_host,'dbname':dbname})

            return render(request, 'mysql_exec.html', locals())
        else:
            return render(request, 'mysql_exec.html', locals())

            # return render(request, 'mysql_exec.html', {'form': form,'objlist':objlist})
    else:
        form = AddForm()
        return render(request, 'mysql_exec.html', locals())

        # return render(request, 'mysql_exec.html', {'form': form,'objlist':objlist})



#
# def mysql_exec(request):
#     #print request.user.username
#     obj_list = func.get_mysql_hostlist(request.user.username,'exec')
#     if request.method == 'POST':
#         form = AddForm(request.POST)
#         if form.is_valid():
#             a = form.cleaned_data['a']
#             c = request.POST['cx']
#             a = func.check_mysql_exec(a,request)
#             #print request.POST
#             if request.POST.has_key('commit'):
#                 (data_mysql,collist,dbname) = func.run_mysql_exec(c,a,request.user.username,request)
#             elif request.POST.has_key('check'):
#                 data_mysql,collist,dbname = incept.inception_check(c,a)
#             return render(request,'mysql_exec.html',{'form': form,'objlist':obj_list,'data_list':data_mysql,'col':collist,'choosed_host':c,'dbname':dbname})
#
#         else:
#             return render(request, 'mysql_exec.html', {'form': form,'objlist':obj_list})
#     else:
#         form = AddForm()
#         return render(request, 'mysql_exec.html', {'form': form,'objlist':obj_list})




@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_see_inception', login_url='/')
def inception(request):
    objlist = func.get_mysql_hostlist(request.user.username,'incept')
    if request.method == 'POST':
        print(">>>>>INCEP.POST:", request.POST)
        if request.POST.has_key('searchdb'):
            db_se = request.POST['searchdbname']
            objlist_tmp = func.get_mysql_hostlist(request.user.username, 'incept', db_se)
            # incase not found any db
            if len(objlist_tmp) > 0:
                objlist = objlist_tmp
        choosed_host = request.POST['cx']  # choose target db
        specification = request.POST['specification'][0:30]
        if not User.objects.get(username=request.user.username).db_name_set.filter(dbtag=choosed_host)[:1]:
            return HttpResponseRedirect("/")
        if request.POST.has_key('check'):
            form = AddForm(request.POST)
            upform = Uploadform()
            if form.is_valid():
                a = form.cleaned_data['a']

                # uploadform/addform add requested=False check
                if len(a.strip()) == 0:
                    return HttpResponseRedirect("/sqlcheck")
                # check done

                # choosed_host = request.POST['cx']
                # get valid statement
                try:
                    tmpsqltext = ''
                    for i in sqlfilter.get_sql_detail(sqlfilter.sql_init_filter(a), 2):
                        tmpsqltext = tmpsqltext + i
                    a = tmpsqltext
                    form = AddForm(initial={'a': a})
                except Exception, e:
                    pass

                data_mysql, collist, dbname = incept.inception_check(choosed_host,a,2)
                #check the nee to split sqltext first
                if len(data_mysql)>1:
                    split = 1
                    return render(request, 'inception.html', {'form': form,'upform':upform,'objlist':objlist,'data_list':data_mysql,'collist':collist,'choosed_host':choosed_host,'split':split})
                else:
                    data_mysql,collist,dbname = incept.inception_check(choosed_host,a)
                    return render(request, 'inception.html', {'form': form,'upform':upform,'objlist':objlist,'data_list':data_mysql,'collist':collist,'choosed_host':choosed_host})
            else:
                # print "not valid"
                return render(request, 'inception.html', {'form': form,'upform':upform,'objlist':objlist})
        elif request.POST.has_key('upload'):
            upform = Uploadform(request.POST,request.FILES)
            #c = request.POST['cx']
            if upform.is_valid() and request.FILES.has_key('filename'):
                #print(">>>>>upform.is_valid(): ",upform.is_valid())
                # choosed_host = request.POST['cx']
                sqltext=''
                for chunk in request.FILES['filename'].chunks():
                    #print chunk
                    try:
                        chunk = chunk.decode('utf8')
                    except Exception,e:
                        chunk = chunk.decode('gbk')
                    sqltext = sqltext + chunk
                # get valid statement
                try:
                    tmpsqltext=''
                    for i in  sqlfilter.get_sql_detail(sqlfilter.sql_init_filter(sqltext), 2):
                        tmpsqltext=tmpsqltext + i
                    sqltext = tmpsqltext
                except Exception, e:
                    pass
                form = AddForm(initial={'a': sqltext})
                return render(request, 'inception.html', {'form': form,'upform':upform,'objlist':objlist,'choosed_host':choosed_host})
            else:
                form = AddForm()
                upform = Uploadform(initial={'filename':''})
                return render(request, 'inception.html', {'form': form,'upform':upform,'objlist':objlist,'upload_btn': 1})
        elif request.POST.has_key('addtask'):
            form = AddForm(request.POST)
            needbackup = (int(request.POST['ifbackup']) if int(request.POST['ifbackup']) in (0,1) else 1)

            # choosed_host = request.POST['cx']
            upform = Uploadform()
            if form.is_valid():
                sqltext = form.cleaned_data['a']

                # uploadform/addform add requested=False check
                if len(sqltext.strip()) == 0:
                    return HttpResponseRedirect("/sqlcheck")
                # check done

                # get valid statement
                try:
                    tmpsqltext = ''
                    for i in sqlfilter.get_sql_detail(sqlfilter.sql_init_filter(sqltext), 2):
                        tmpsqltext = tmpsqltext + i
                    sqltext = tmpsqltext
                    form = AddForm(initial={'a': sqltext})
                except Exception, e:
                    pass
                data_mysql, tmp_col, dbname = incept.inception_check(choosed_host, sqltext, 2)
                # check if the sqltext need to be splited before uploaded
                if len(data_mysql)>1:
                    split = 1
                    status = 'UPLOAD TASK FAIL; DDL DML NEED SPLIT.'
                    return render(request, 'inception.html',{'form': form, 'upform': upform, 'objlist': objlist, 'status': status,'split':split,'choosed_host':choosed_host})
                #check sqltext before uploaded
                else:
                    tmp_data, tmp_col, dbname = incept.inception_check(choosed_host, sqltext)
                    for i in tmp_data:
                        if int(i[2]) !=0:
                            status = 'UPLOAD TASK FAIL,CHECK NOT PASSED; AFTER CHECK PASSED, SUBMITTED TASK.'
                            return render(request, 'inception.html',locals())
                incept.record_task(request,sqltext,choosed_host,specification,needbackup)
                status='UPLOAD TASK OK'
                sendmail_task.delay(choosed_host+'\n'+sqltext)
                return render(request, 'inception.html', {'form': form,'upform':upform,'objlist':objlist,'status':status,'choosed_host':choosed_host})
            else:
                status='UPLOAD TASK FAIL'
                return render(request, 'inception.html', {'form': form,'upform':upform,'objlist':objlist,'status':status,'choosed_host':choosed_host})
        form = AddForm()  # initial={'a': ''})  # only "searchdb" button submit
        upform = Uploadform()  # initial={'filename': ''})  # only "searchdb" button submit
        return render(request, 'inception.html', {'form': form, 'upform': upform, 'objlist': objlist,'choosed_host':choosed_host})
    else:
        form = AddForm()
        upform = Uploadform()
        return render(request, 'inception.html', {'form': form,'upform':upform,'objlist':objlist})

'''
def login(request):
    try:
        cookie = request.COOKIES['CHEHEJIASESSIONID']
        # check someone login,get userInfo
        #https://boss.dev.chehejia.com/newAuth/login?serviceId=db&serviceUrl=&noc=boss-76811ca3244e458bb8e489b131724d21
        #opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie))
        #url = "https://boss.dev.chehejia.com/?serviceId=db"
        url = "https://boss.dev.chehejia.com/newAuth/login?serviceId=db&serviceUrl=&noc={}".format(cookie)
        #headers = {"noc": cookie}
        print("url::", url)
        #data = {"noc": cookie}
        req = urllib2.Request(url)
        response = urllib2.urlopen(req)
        print('cookies>>',request.COOKIES,':::', cookie)
        try:
            res_str = response.read()
            res_dict = json.loads(res_str)
            userInfo = json.loads(res_dict['userInfo'])
            email = userInfo["email"]
            username = userInfo["email"].split('@')[0]
            password = userInfo["mobile"]
            add_user(username,password,email)
            user = auth.authenticate(username=username, password=password)
            auth.login(request, user)
            func.log_userlogin(request)
            #return HttpResponseRedirect("https://boss.dev.chehejia.com/?serviceId=db")
            return HttpResponseRedirect("/")
        except Exception as e:
            print('LOGIN ERROR >>> No JSON data return: %s' % e)
            # return HttpResponse("login succ")
            return HttpResponseRedirect("https://boss.dev.chehejia.com/?serviceId=db")
    except Exception as e:
        print("login goes wrong! mess:%s" % e)
        #redirect
        return HttpResponseRedirect("https://boss.dev.chehejia.com/?serviceId=db")

def add_user(uname,pwd,email):
    user_str = User.objects.filter(username=uname)
    if len(user_str) > 0:
        print("get record:{}".format(uname))
        upd_pwd = User.objects.get(username=uname)
        print("upd_pwd:",upd_pwd,'pwd:',pwd,'email:',email)
        upd_pwd.set_password(pwd)
        upd_pwd.save()
        # update db_user_pwd row data
        try:
            upd_pwd.db_user_pwd.pwd = pwd
            upd_pwd.db_user_pwd.save()
        except Exception as e:
            print("add_user >> RelatedObjectDoesNotExist: upd_pwd[User][%s] has no db_user_pwd.Create new db_user_pwd line." % e)
            newpwd = Db_user_pwd(user=upd_pwd,pwd=pwd)
            newpwd.save()
    else:
        CreateUser = User.objects.create_user(username=uname,
                                              password=pwd,
                                              email=email,)
        if email in config.dbamails:
            CreateUser.is_superuser = True
            CreateUser.is_staff = True
            CreateUser.is_active = True
            CreateUser.last_login = datetime.datetime.now()
            CreateUser.save()
            try:
                u = User.objects.get(username=uname)
                newpwd = Db_user_pwd(user=u,pwd=pwd)
                newpwd.save()
            except Exception as e:
                print("create/change pwd save failed {}".format(str(e)))


'''
# @ratelimit(key=func.my_key,method='POST', rate='5/15m')
def login(request):
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        form = LoginForm()
        myform = Captcha()
        error = 1
        # return render_to_response('login.html', RequestContext(request, {'form': form,'myform':myform,'error':error}))
        return render(request, 'login.html', {'form': form, 'myform': myform, 'error': error})
    else:
        if request.user.is_authenticated():
            return render(request, 'include/base.html')
        else:
            if request.GET.get('newsn')=='1':
                csn=CaptchaStore.generate_key()
                cimageurl= captcha_image_url(csn)
                return HttpResponse(cimageurl)
            elif  request.method == "POST":
                form = LoginForm(request.POST)
                myform = Captcha(request.POST)
                if myform.is_valid():
                    if form.is_valid():
                        username = form.cleaned_data['username']
                        password = form.cleaned_data['password']
                        user = auth.authenticate(username=username, password=password)
                        if user is not None and user.is_active:
                            auth.login(request, user)
                            func.log_userlogin(request)
                            return HttpResponseRedirect("/")
                        else:
                            # login failed
                            func.log_loginfailed(request, username)
                            # request.session["wrong_login"] =  request.session["wrong_login"]+1
                            # return render_to_response('login.html', RequestContext(request, {'form': form,'myform':myform,'password_is_wrong':True}))
                            return render(request, 'login.html', {'form': form,'myform':myform,'password_is_wrong':True})
                    else:
                        #return render_to_response('login.html', RequestContext(request, {'form': form,'myform':myform}))
                        return render(request, 'login.html', {'form': form,'myform':myform})
                else :
                    #cha_error
                    form = LoginForm(request.POST)
                    myform = Captcha(request.POST)
                    chaerror = 1
                    # return render_to_response('login.html', RequestContext(request, {'form': form,'myform':myform,'chaerror':chaerror}))
                    return render(request, 'login.html', {'form': form, 'myform': myform, 'chaerror': chaerror})
            else:
                form = LoginForm()
                myform = Captcha()
                #return render_to_response('login.html', RequestContext(request, {'form': form,'myform':myform}))
                return render(request, 'login.html', {'form': form, 'myform': myform})





#
# @login_required(login_url='/accounts/login/')
# def upload_file(request):
#     if request.method == "POST":
#         form = Uploadform(request.POST,request.FILES)
#         if form.is_valid():
#         #username = request.user.username
#             username ='test'
#             filename = form.cleaned_data['filename']
#             myfile = Upload()
#             myfile.username = username
#             myfile.filename = filename
#             myfile.save()
#             print myfile.filename.url
#             print myfile.filename.path
#             print myfile.filename.name
#             print ""
#             for chunk in request.FILES['filename'].chunks():
#                 sqltext = sqltext + chunk
#             print sqltext
#             f = open(myfile.filename.path,'r')
#             result = list()
#             for line in f.readlines():
#                 #print line
#                 result.append(line)
#             print "what the fuck"
#             print result
#             return HttpResponse('upload ok!')
#         else :
#             return HttpResponse('upload false!')
#     else:
#         form = Uploadform()
#         return  render(request, 'upload.html', {'form': form})

@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_see_taskview', login_url='/')
def get_rollback(request):
    idnum = request.GET['taskid']
    if request.user.username == Task.objects.get(id=idnum).user:
        sqllist = incept.rollback_sqllist(idnum)
    # print sqllist
    return HttpResponse(json.dumps(sqllist), content_type='application/json')

@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_see_taskview', login_url='/')
def get_single_rollback(request):
    sequence = request.GET['sequenceid']
    sqllist = incept.rollback_sql(sequence)
    return HttpResponse(json.dumps(sqllist), content_type='application/json')

@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_see_taskview', login_url='/')
def task_manager(request):
    #obj_list = func.get_mysql_hostlist(request.user.username,'log')
    obj_list = ['all'] + func.get_mysql_hostlist(request.user.username,'incept')
    if request.method == 'POST' :
        form = Taskquery(request.POST)
        form2 = Taskscheduler(request.POST)
        if form.is_valid():
            endtime = form.cleaned_data['end']
        else:
            endtime = datetime.datetime.now()
        if form2.is_valid():
            sche_time = form2.cleaned_data['sche_time']
            # print sche_time
        else:
            sche_time = datetime.datetime.now()
        hosttag = request.POST['hosttag']
        data = incept.get_task_list(hosttag, request, endtime)
        if request.POST.has_key('commit'):
            # data = incept.get_task_list(hosttag,request,endtime)
            return render(request,'task_manager.html',{'form':form,'form2':form2,'objlist':obj_list,'datalist':data,'choosed_host':hosttag})
        elif request.POST.has_key('delete') and (request.user.has_perm('myapp.can_admin_task') or request.user.has_perm('myapp.can_delete_task')):
            id = int(request.POST['delete'])
            incept.delete_task(id)
            return render(request,'task_manager.html',{'form':form,'form2':form2,'objlist':obj_list,'datalist':data,'choosed_host':hosttag})
        elif request.POST.has_key('check'):
            id = int(request.POST['check'])
            results,col,tar_dbname = incept.task_check(id,request)
            return render(request,'task_manager.html',{'form':form,'form2':form2,'objlist':obj_list,'datalist':data,'choosed_host':hosttag,'result':results,'col':col})
        elif request.POST.has_key('see_running'):
            id = int(request.POST['see_running'])
            request.session['recent_taskid'] = id
            results,cols = incept.task_running_status(id)
            return render(request,'task_manager.html',{'form':form,'form2':form2,'objlist':obj_list,'datalist':data,'choosed_host':hosttag,'result_status':results,'cols':cols})
        elif request.POST.has_key('exec') and request.user.has_perm('myapp.can_admin_task'):
            id = int(request.POST['exec'])
            nllflag = task_run(id,request)
            #nllflag = task_run.delay(id)
            # print nllflag
            return render(request,'task_manager.html',{'form':form,'form2':form2,'objlist':obj_list,'datalist':data,'choosed_host':hosttag,'nllflag':nllflag})
        elif request.POST.has_key('stop') and request.user.has_perm('myapp.can_admin_task'):
            sqlsha = request.POST['stop']
            # incept.incep_stop(sqlsha,request)
            results,cols  = incept.incep_stop(sqlsha,request)
            return render(request,'task_manager.html',{'form':form,'form2':form2,'objlist':obj_list,'datalist':data,'choosed_host':hosttag,'result_status':results,'cols':cols})
        elif request.POST.has_key('appoint') and request.user.has_perm('myapp.can_admin_task'):
            id = int(request.POST['appoint'])
            incept.set_schetime(id,sche_time)
            return render(request, 'task_manager.html',{'form': form,'form2':form2, 'objlist': obj_list, 'datalist': data, 'choosed_host': hosttag})
        elif request.POST.has_key('update'):
            id = int(request.POST['update'])

            # response = HttpResponseRedirect("/update_task/")
            # response.set_cookie('update_taskid',id)
            # return response

            request.session['update_taskid']=id
            return HttpResponseRedirect("/update_task/")
        elif request.POST.has_key('export_task'):
            task_id_list = request.POST.getlist('choosedlist')
            charset = request.POST['charset']
            data_list = Task.objects.filter(id__in= task_id_list)
            pseudo_buffer = Echo()
            writer = csv.writer(pseudo_buffer)
            results_list = []
            a = u'zhongwen'
            for i in data_list:
                if type(i.sqltext) == type(a):
                    if charset =="GB18030":
                        results_list.append([i.id,i.dbtag,i.sqltext.encode('gb18030')])
                    elif charset=="UTF8":
                        results_list.append([i.id, i.dbtag, i.sqltext.encode('utf8')])

            response = StreamingHttpResponse((writer.writerow(row) for row in results_list), content_type="text/csv")
            response['Content-Disposition'] = 'attachment; filename="task_export.csv"'
            return response
        else:
            return HttpResponseRedirect("/")
    else:
        data = incept.get_task_list('all',request,datetime.datetime.now())
        form = Taskquery()
        form2 = Taskscheduler()
        return render(request, 'task_manager.html', {'form':form,'form2':form2,'objlist':obj_list,'datalist':data})

#test

@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_see_taskview', login_url='/')
def update_task(request):
    try:
        # id = int(request.COOKIES["update_taskid"])
        id = request.session['update_taskid']
        data = incept.get_task_forupdate(id)
    except Exception,e:
        str = "ERROR! ID NOT EXISTS , PLEASE CHECK !"
        #return render(request, 'update_task.html', {'str': str})
        return render(request, 'update_task.html', locals())
    objlist = func.get_mysql_hostlist(request.user.username, 'incept')
    if request.method == 'POST':
        if request.POST.has_key('update'):
            needbackup = (int(request.POST['ifbackup']) if int(request.POST['ifbackup']) in (0,1,2) else 1)

            #update task function can't change db
            flag,str = incept.check_task_status(id)
            if flag:
                sqltext = request.POST['sqltext']
                specify = request.POST['specify'][0:30]
                try:
                    mystatus = request.POST['status']
                except Exception,e:
                    mystatus = data.status
                # choosed_host = data.dbtag
                # data_mysql, tmp_col, dbname = incept.inception_check(choosed_host, sqltext, 2)
                #
                # # check if the sqltext need to be splited before uploaded
                # if len(data_mysql) > 1:
                #     str = 'SPLICT THE SQL FIRST'
                #     return render(request, 'update_task.html', {'str': str})
                # # check sqltext before uploaded
                # else:
                #     tmp_data, tmp_col, dbname = incept.inception_check(choosed_host, sqltext)
                #     for i in tmp_data:
                #         if int(i[2]) != 0:
                #             str = 'UPDATE TASK FAIL,CHECK NOT PASSED'
                #             return render(request, 'update_task.html', {'str': str})
                incept.update_task(id, sqltext, specify,mystatus,needbackup,request.user.username)
                return HttpResponseRedirect("/task/")
            else:
                # return render(request, 'update_task.html', {'str': str})
                return render(request, 'update_task.html', {'str': str})
        elif request.POST.has_key('new_task'):
            #new_task can only change the dbtag
            needbackup = (int(request.POST['ifbackup']) if int(request.POST['ifbackup']) in (0,1) else 1)

            choosed_host = request.POST['hosttag']
            if data.dbtag == choosed_host:
                str = 'DB HASN\'T CHANGED! CAN\'T CREATE NEW!'
                return render(request, 'update_task.html', {'str': str})
            data_mysql, tmp_col, dbname = incept.inception_check(choosed_host, data.sqltext, 2)

            # check if the sqltext need to be splited before uploaded
            if len(data_mysql) > 1:
                str = 'SPLICT THE SQL FIRST'
                return render(request, 'update_task.html', {'str': str})
            # check sqltext before uploaded
            else:
                tmp_data, tmp_col, dbname = incept.inception_check(choosed_host, data.sqltext)
                for i in tmp_data:
                    if int(i[2]) != 0:
                        str = 'CREATE NEW TASK FAIL,CHECK NOT PASSED'
                        return render(request, 'update_task.html', {'str': str})
            incept.record_task(request, data.sqltext, choosed_host, data.specification,needbackup)
            sendmail_task.delay(choosed_host + '\n' + data.sqltext)
            return HttpResponseRedirect("/task/")

        elif request.POST.has_key('searchdb'):
            db_se = request.POST['searchname']
            objlist = func.get_mysql_hostlist(request.user.username, 'incept',db_se)
            if len(objlist) == 0 :
                objlist = [data.dbtag,]
            return render(request, 'update_task.html', locals())
    else:
        return render(request, 'update_task.html', locals())



# def update_task(request):
#     try:
#         # id = int(request.COOKIES["update_taskid"])
#         id = request.session['update_taskid']
#     except Exception,e:
#         str = "ERROR"
#         #return render(request, 'update_task.html', {'str': str})
#         return render(request, 'update_task.html', locals())
#     if request.method == 'POST':
#         if request.POST.has_key('update'):
#             flag,str = incept.check_task_status(id)
#             if flag:
#                 sqltext = request.POST['sqltext']
#                 specify = request.POST['specify'][0:30]
#                 mystatus = request.POST['status']
#                 incept.update_task(id, sqltext, specify,mystatus)
#                 return HttpResponseRedirect("/task/")
#             else:
#                 # return render(request, 'update_task.html', {'str': str})
#                 return render(request, 'update_task.html', locals())
#         elif request.POST.has_key('new_task'):
#             pass
#     else:
#         try:
#             data = incept.get_task_forupdate(id)
#             # return render(request, 'update_task.html', {'data': data})
#             return render(request, 'update_task.html', locals())
#         except Exception,e:
#             str = "ID NOT EXISTS , PLEASE CHECK !"
#             # return render(request, 'update_task.html', {'str': str})
#             return render(request, 'update_task.html', locals())

@login_required(login_url='/accounts/login/')
def list_instances(request):
    if request.user.has_perm('myapp.can_grant_db'):
        obj_ins = Db_instance.objects.all()
        return render(request,'previliges/list_instances.html',{'inslist':obj_ins,'status': 'ok'})
    else:
        return render(request,'previliges/list_instances.html',{'status': 'notok'})

@login_required(login_url='/accounts/login/')
def grant_privileges(request):
    if request.user.has_perm('myapp.can_grant_db'):
        #show every dbtags
        #obj_list = func.get_mysql_hostlist(request.user.username,'log')
        #show dbtags permitted to the user
        obj_list = func.get_mysql_hostlist(request.user.username,'log')
        optype_list = func.get_op_type()
        mysql_privs = func.get_db_privs()
        if request.method == 'POST' :
            form = Logquery(request.POST)
            # with_time_submit for search
            if request.POST.has_key('with_time_submit'):
                if form.is_valid():
                    begintime = form.cleaned_data['begin']
                    endtime = form.cleaned_data['end']
                    hosttag = str(request.POST['hosttag']).strip()
                    optype = request.POST['optype']
                    addr, dbname, idc = func.get_instance_addr(hosttag)

                    data = func.get_privileges_data(hosttag,optype,begintime,endtime)
                    for item in data:
                        item.grant_user_pwd = func.get_decrypt_pwd(item.grant_user_pwd)

                    return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list,'datalist':data,'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'addr': addr, 'dbname': dbname})
            elif request.POST.has_key('confirm_add'):
                hosttag = str(request.POST['ins_host_add']).strip()
                data = func.get_privileges_data(hosttag)
                for item in data:
                    item.grant_user_pwd = func.get_decrypt_pwd(item.grant_user_pwd)
                addr, dbname, idc = func.get_instance_addr(hosttag)

                print("confirm_add>>>:", request.POST)
                #post_data=request.POST.getlist('to[]')
                pwd, enpwd = func.random_pwd()
                try:
                    grant_dbtag = request.POST['ins_host_add'].strip()
                    grant_user = request.POST['grant_user_add'].strip()
                    grant_ip = request.POST['grant_host_add'].strip()
                    grant_privs = ','.join(request.POST.getlist('to[]'))
                    grant_db = request.POST['grant_db_add'].strip()
                    grant_tables=request.POST['grant_tbs_add'].strip()
                    grant_user_pwd = pwd
                    grant_comment=request.POST['remark'].strip()

                    # Current NOT support grant_db = '*' check grant_db
                    if grant_db == '*':
                        ret = 'Grant_db equal "*" not support current,Please give DB_NAME.'
                        return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'datalist':data, 'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'err_msg': ret, 'addr': addr, 'dbname': dbname})
                    # check done

                    dbtool = DBTool(username=opsdbuser, password=func.get_mypd(),database='mysql', host=addr.split(':')[1], port=int(addr.split(':')[2]))
                    print('>>>dbtool:',dbtool)
                    #print(">>>>dbtool parms:", opsdbuser,':', func.get_mypd(),':', addr.split(':')[1],',',int(addr.split(':')[2]))

                    ret, status = func.add_new_priv(dbtool, grant_privs, grant_db, grant_tables, grant_user, grant_ip, grant_user_pwd, idc)
                    if status == 'ok':
                        ###
                        dbs = [db.strip() for db in grant_db.split(',') if len(db.strip()) > 0]
                        prefix_tag = func.get_prefix(grant_dbtag)
                        print("prefix_tag>>>", prefix_tag)
                        for db in dbs:
                            sep = db.replace('_', '-')
                            dbtag = prefix_tag + '-' + str(sep)
                            print("sep:",sep,"dbtag::",dbtag)
                            # SIGN RECORD
                            priv = Db_privileges(grant_dbtag=dbtag,grant_user=request.POST['grant_user_add'],grant_ip=request.POST['grant_host_add'],
                                         grant_privs=','.join(request.POST.getlist('to[]')),
                                         grant_db=request.POST['grant_db_add'],grant_tables=request.POST['grant_tbs_add'],
                                         grant_user_pwd=enpwd,grant_comment=request.POST['remark'],db_name_id=Db_name.objects.get(dbtag=dbtag).id)
                            priv.save()
                            priv_log = DB_priv_log(uname=request.user.username, action="add_new_priv", fkid_id=Db_privileges.objects.last().id)
                            priv_log.save()
                        ###
                        # -- select privs_data again
                        data = func.get_privileges_data(hosttag)
                        for item in data:
                            item.grant_user_pwd = func.get_decrypt_pwd(item.grant_user_pwd)
                        # -- select privs_data again done
                    else:
                        return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'datalist':data, 'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'err_msg': ret, 'addr': addr, 'dbname': dbname})

                except Exception as e:
                    print("confirm_add error: ", e)
                    return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'datalist':data, 'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'err_msg': e, 'addr': addr, 'dbname': dbname})
                return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'datalist':data, 'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'addr': addr, 'dbname': dbname})

            elif request.POST.has_key('confirm_modify'):
                hosttag = str(request.POST['ins_host_add']).strip()
                data = func.get_privileges_data(hosttag)
                for item in data:
                    item.grant_user_pwd = func.get_decrypt_pwd(item.grant_user_pwd)
                addr, dbname, idc = func.get_instance_addr(hosttag)
                try:
                    grant_id = int(request.POST['confirm_modify'].strip())
                    grant_dbtag = request.POST['ins_host_add'].strip()
                    grant_user = request.POST['grant_user_add'].strip()
                    grant_ip = request.POST['grant_host_add'].strip()
                    grant_privs = ','.join(request.POST.getlist('to[]'))
                    grant_db = request.POST['grant_db_add'].strip()
                    grant_tables=request.POST['grant_tbs_add'].strip()
                    # grant_user_pwd = pwd
                    grant_comment=request.POST['remark'].strip()

                    # Current NOT support grant_db = '*' check grant_db
                    if grant_db == '*':
                        ret = 'Grant_db equal "*" not support current,Please give DB_NAME.'
                        return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'datalist':data, 'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'err_msg': ret, 'addr': addr, 'dbname': dbname})
                    # check done

                    dbtool = DBTool(username=opsdbuser, password=func.get_mypd(),database='mysql', host=addr.split(':')[1], port=int(addr.split(':')[2]))

                    ret, status = func.modify_priv(request, dbtool, grant_id, grant_privs, grant_db, grant_tables, grant_user, grant_ip, grant_comment, idc)
                except Exception as e:
                    print("confirm_modify: ", e)

                    return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'datalist':data, 'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'err_msg': e, 'addr': addr, 'dbname': dbname})
                # -- succ
                data = func.get_privileges_data(hosttag)
                for item in data:
                    item.grant_user_pwd = func.get_decrypt_pwd(item.grant_user_pwd)
                # -- succ done
                return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'datalist':data, 'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'err_msg': ret, 'addr': addr, 'dbname': dbname})

            elif request.POST.has_key('confirm_add_ip'):
                print(">>>>>add_ip:", request.POST)
                hosttag = str(request.POST['ins_host_add']).strip()
                data = func.get_privileges_data(hosttag)
                for item in data:
                    item.grant_user_pwd = func.get_decrypt_pwd(item.grant_user_pwd)
                addr, dbname, idc = func.get_instance_addr(hosttag)

                try:
                    grant_id = int(request.POST['confirm_add_ip'].strip())
                    grant_user = request.POST['grant_user_add'].strip()
                    grant_ip = request.POST['grant_host_add'].strip()
                    grant_comment = request.POST['remark'].strip()

                    dbtool = DBTool(username=opsdbuser, password=func.get_mypd(),database='mysql', host=addr.split(':')[1], port=int(addr.split(':')[2]))

                    ret, status = func.confirm_add_ip(dbtool, grant_id, hosttag, grant_user, grant_ip, grant_comment)
                except Exception as e:
                    print("confirm_add_ip: ", e)
                    return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'datalist':data, 'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'err_msg': e, 'addr': addr, 'dbname': dbname})
                # -- succ
                data = func.get_privileges_data(hosttag)
                for item in data:
                    item.grant_user_pwd = func.get_decrypt_pwd(item.grant_user_pwd)
                # -- succ done
                return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'datalist':data, 'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'err_msg': ret, 'addr': addr, 'dbname': dbname})

            elif request.POST.has_key('confirm_update_pwd'):
                print(">>>> confirm_update_pwd: ", request.POST)
                hosttag = str(request.POST['ins_host_add']).strip()
                data = func.get_privileges_data(hosttag)
                for item in data:
                    item.grant_user_pwd = func.get_decrypt_pwd(item.grant_user_pwd)
                addr, dbname, idc = func.get_instance_addr(hosttag)

                dbtool = DBTool(username=opsdbuser, password=func.get_mypd(),database='mysql', host=addr.split(':')[1], port=int(addr.split(':')[2]))

                try:
                    grant_id = int(request.POST['confirm_update_pwd'].strip())
                    grant_user = request.POST['grant_user_add'].strip()
                    grant_ip = request.POST['grant_host_add'].strip()
                    grant_comment = request.POST['remark'].strip()
                    update_user_pwd = request.POST['update_pwd_add'].strip()

                    dbtool = DBTool(username=opsdbuser, password=func.get_mypd(),database='mysql', host=addr.split(':')[1], port=int(addr.split(':')[2]))

                    ret, status = func.confirm_update_pwd(dbtool, grant_id, hosttag, grant_user, grant_ip, update_user_pwd,grant_comment)
                except Exception as e:
                    print("confirm_update_pwd: ", e)
                    return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'datalist':data, 'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'err_msg': e, 'addr': addr, 'dbname': dbname})

                # -- succ
                data = func.get_privileges_data(hosttag)
                for item in data:
                    item.grant_user_pwd = func.get_decrypt_pwd(item.grant_user_pwd)
                # -- succ done
                return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'datalist':data, 'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'err_msg': ret, 'addr': addr, 'dbname': dbname})

            elif request.POST.has_key('delete'):
                print(">>>> delete :", request.POST)
                hosttag = str(request.POST['ins_host_add']).strip()
                data = func.get_privileges_data(hosttag)
                for item in data:
                    item.grant_user_pwd = func.get_decrypt_pwd(item.grant_user_pwd)
                addr, dbname, idc = func.get_instance_addr(hosttag)

                try:
                    grant_id = int(request.POST['grant_id'].strip())

                    dbtool = DBTool(username=opsdbuser, password=func.get_mypd(),database='mysql', host=addr.split(':')[1], port=int(addr.split(':')[2]))

                    ret, status = func.confirm_delete(dbtool, grant_id, hosttag)
                except Exception as e:
                    print("confirm_delete: ", e)
                    return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'datalist':data, 'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'err_msg': e, 'addr': addr, 'dbname': dbname})

                # -- succ
                data = func.get_privileges_data(hosttag)
                for item in data:
                    item.grant_user_pwd = func.get_decrypt_pwd(item.grant_user_pwd)
                # -- succ done
                return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'datalist':data, 'choosed_host':hosttag, 'mysql_privs': mysql_privs, 'err_msg': ret, 'addr': addr, 'dbname': dbname})

            else:
                print "not valid"
                return render(request,'previliges/grant_privileges.html',{'form': form,'objlist':obj_list,'optypelist':optype_list, 'mysql_privs': mysql_privs})
        else:
            addr, dbname, idc = func.get_instance_addr(obj_list[0])
            form = Logquery()
            return render(request, 'previliges/grant_privileges.html', {'form': form,'objlist':obj_list,'optypelist':optype_list, 'mysql_privs': mysql_privs, 'addr':addr, 'dbname': dbname})

@login_required(login_url='/accounts/login/')
def pre_query(request):
    if request.user.has_perm('myapp.can_query_pri') or request.user.has_perm('myapp.can_set_pri') :
        objlist = func.get_mysql_hostlist(request.user.username,'log')
        usergroup = Db_group.objects.all().order_by('groupname')
        inslist = Db_instance.objects.filter(role__in=['read','write','all']).order_by('ip')
        if request.method == 'POST':
            if request.POST.has_key('queryuser'):
            # if request.POST.has_key('accountname') and request.POST['accountname']!='':
                try:
                    username = request.POST['accountname']
                    dbgp, usergp = func.get_user_grouppri(username)

                    pri = func.get_privileges(username)
                    profile = []
                    try:
                        profile = User.objects.get(username=username).user_profile
                    except Exception,e:
                        pass
                    userdblist,info = func.get_user_pre(username,request)
                    ur = User.objects.get(username=username)
                    return render(request, 'previliges/prequery.html', {'inslist':inslist,'pri':pri, 'profile':profile, 'dbgp':dbgp, 'usergp':usergp, 'objlist':objlist, 'userdblist': userdblist, 'info':info, 'usergroup':usergroup,'ur':ur})
                except Exception,e:
                    return render(request, 'previliges/prequery.html', {'inslist':inslist,'objlist':objlist, 'usergroup':usergroup})
            elif request.POST.has_key('querydb'):
                try:
                    choosed_host = request.POST['cx']
                    data,instance,acc,gp = func.get_pre(choosed_host)
                    return render(request, 'previliges/prequery.html', {'inslist':inslist,'objlist':objlist, 'choosed_host':choosed_host, 'data_list':data, 'ins_list':instance, 'acc':acc,'gp':gp, 'usergroup':usergroup})
                except Exception, e:
                    return render(request, 'previliges/prequery.html', {'inslist':inslist,'objlist': objlist, 'usergroup': usergroup})
            elif request.POST.has_key('querygp'):
                try:
                    choosed_gp = request.POST['choosed_gp']
                    dbgroup = func.get_groupdb(choosed_gp)
                    return render(request, 'previliges/prequery.html', {'inslist':inslist,'objlist': objlist, 'dbgroup':dbgroup, 'usergroup': usergroup})
                except Exception,e:
                    return render(request, 'previliges/prequery.html', {'inslist':inslist,'objlist': objlist, 'usergroup': usergroup})
            elif request.POST.has_key('queryins'):
                try:
                    insname = Db_instance.objects.get(id=int(request.POST['ins_set']))
                    tmpli = []
                    for i in insname.db_name_set.all():
                        for x in i.instance.all():
                            tmpli.append(int(x.id))
                    tmpli = list(set(tmpli))
                    bro = Db_instance.objects.filter(id__in=tmpli)
                    return render(request, 'previliges/prequery.html', locals())
                except Exception,e:
                    return render(request, 'previliges/prequery.html', locals())

        else:
            return render(request, 'previliges/prequery.html', locals())
    else:
        return HttpResponseRedirect("/")

@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_set_pri', login_url='/')
def pre_set(request):
    userlist,grouplist = func.get_UserAndGroup()
    usergroup=func.get_usergp_list()
    dblist = Db_name.objects.all().order_by('dbtag')
    public_user = func.public_user
    if request.method == 'POST':
        username = request.POST['account']
        if request.POST.has_key('set'):
            try :
                dbgplist = request.POST.getlist('choosedlist')
                group = request.POST.getlist('user_group')
                ch_db = request.POST.getlist('user_dblist')
                #change username or password
                new_username = request.POST['newname']
                new_passwd = request.POST['newpasswd']
                mail = request.POST['newmail']
                if len(new_username)>0:
                    tmp = User.objects.get(username=username)
                    tmp.username = new_username
                    tmp.save()
                    username = new_username
                if len(new_passwd)>0:
                    tmp = User.objects.get(username=username)
                    tmp.set_password(new_passwd)
                    tmp.save()
                # if len(new_mail) > 0:
                #update mail

                tmp = User.objects.get(username=username)
                tmp.email = mail
                tmp.save()

                func.clear_userpri(username)
                func.set_groupdb(username,dbgplist)
                user = User.objects.get(username=username)
                func.set_usergroup(user, group)
                func.set_user_db(user, ch_db)
                info = 'SET USER ' + username + '  OK!'
                userlist = User.objects.exclude(username=public_user).order_by('username')
                return render(request, 'previliges/pre_set.html', {'mail':mail,'username':username,'info':info, 'dblist':dblist, 'userlist': userlist, 'grouplist': grouplist, 'usergroup':usergroup})
            except Exception,e:
                info = 'SET USER ' + username + '  FAILED!'
                return render(request, 'previliges/pre_set.html', {'info':info, 'dblist':dblist, 'userlist': userlist, 'grouplist': grouplist, 'usergroup':usergroup})
        elif request.POST.has_key('reset'):
            func.clear_userpri(username)
            info = 'RESET USER '+ username + '  OK!'
            return render(request, 'previliges/pre_set.html', {'info':info, 'dblist':dblist, 'userlist': userlist, 'grouplist': grouplist, 'usergroup':usergroup})
        elif request.POST.has_key('query'):
            try:
                dbgp,usergp = func.get_user_grouppri(username)
                userdblist,info = func.get_user_pre(username, request)
                mail = User.objects.get(username = username).email
                return render(request, 'previliges/pre_set.html', {'mail':mail,'username':username, 'dbgp':dbgp, 'usergp':usergp, 'userdblist':userdblist, 'dblist':dblist, 'userlist': userlist, 'grouplist': grouplist, 'usergroup':usergroup})
            except Exception,e:
                return render(request, 'previliges/pre_set.html',{'dblist': dblist, 'userlist': userlist, 'grouplist': grouplist, 'usergroup': usergroup})

        elif request.POST.has_key('delete'):
            try:
                info = 'DELETE USER ' + username + '  OK!'
                func.delete_user(username)
                userlist = User.objects.exclude(username=public_user)
                return render(request, 'previliges/pre_set.html',{'info': info, 'dblist': dblist, 'userlist': userlist, 'grouplist': grouplist,'usergroup': usergroup})
            except Exception,e:
                info = 'DELETE USER ' + username + '  FAILED!'
                return render(request, 'previliges/pre_set.html', {'info': info, 'dblist': dblist, 'userlist': userlist, 'grouplist': grouplist,'usergroup': usergroup})
        elif  request.POST.has_key('create'):
            try:
                username = request.POST['newname']
                passwd = request.POST['newpasswd']
                mail = request.POST['newmail']
                group = request.POST.getlist('user_group')
                dbgplist = request.POST.getlist('choosedlist')
                ch_db = request.POST.getlist('user_dblist')
                user = func.create_user(username,passwd,mail)
                func.set_groupdb(username, dbgplist)
                func.set_user_db(user, ch_db)
                func.set_usergroup(user,group)
                info = "CREATE USER SUCCESS!"
                userlist = User.objects.exclude(username=public_user).order_by('username')
                return render(request, 'previliges/pre_set.html', {'user':user,'info':info, 'dblist':dblist, 'userlist': userlist, 'grouplist': grouplist, 'usergroup':usergroup})
            except Exception,e:
                info = "CREATE USER FAILED!"
                return render(request, 'previliges/pre_set.html', {'info':info, 'dblist':dblist, 'userlist': userlist, 'grouplist': grouplist, 'usergroup':usergroup})
    else:
        pri.init_ugroup
        return render(request, 'previliges/pre_set.html', {'dblist':dblist, 'userlist':userlist, 'grouplist':grouplist, 'usergroup':usergroup})


@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_set_pri', login_url='/')
def set_dbgroup(request):
    public_user = func.public_user
    dbgrouplist,userlist,dbnamelist = pri.get_full()
    if request.method == 'POST':
        if request.POST.has_key('query'):
            try:
                groupname = request.POST['dbgroup_set']
                s_dbnamelist,s_userlist = pri.get_group_detail(groupname)
                return render(request, 'previliges/db_group.html', locals())
            except Exception,e:
                return render(request, 'previliges/db_group.html', locals())
        elif request.POST.has_key('create'):
            try:
                info = "CREATE OK!"
                groupname = request.POST['newname']
                dbnamesetlist = request.POST.getlist('dbname_set')
                usersetlist = request.POST.getlist('user_set')
                s_dbnamelist,s_userlist = pri.create_dbgroup(groupname,dbnamesetlist,usersetlist)
                return render(request, 'previliges/db_group.html', locals())
            except Exception,e:
                info = "CREATE FAILED!"
                return render(request, 'previliges/db_group.html', locals())
        elif request.POST.has_key('set'):
            try:
                info = "SET OK!"
                groupname = request.POST['dbgroup_set']
                new_groupname = request.POST['newname']
                a =request.POST.getlist('dbname_set')
                b =  request.POST.getlist('user_set')
                #rename group name
                if len(groupname)>0:
                    tmp = Db_group.objects.get(groupname=groupname)
                    tmp.groupname = new_groupname
                    tmp.save()
                    groupname = new_groupname

                s_dbnamelist, s_userlist = pri.set_dbgroup(groupname, a, b)
                return render(request, 'previliges/db_group.html', locals())
            except Exception,e:
                info = "SET FAILED"
                return render(request, 'previliges/db_group.html', locals())

        elif request.POST.has_key('delete'):
            try:
                info = "DELETE OK!"
                groupname = request.POST['dbgroup_set']
                pri.del_dbgroup(groupname)
                return render(request, 'previliges/db_group.html', locals())
            except Exception,e:
                info = "DELETE FAILED!"
                return render(request, 'previliges/db_group.html', locals())
    else:
        return render(request,'previliges/db_group.html',locals())

@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_set_pri', login_url='/')
def set_ugroup(request):
    public_user = func.public_user
    grouplist, perlist,userlist = pri.get_full_per()
    if request.method == 'POST':
        if request.POST.has_key('query'):
            try:
                groupname = request.POST['group_set']
                s_perlist,s_userlist = pri.get_ugroup_detail(groupname)
                return render(request, 'previliges/u_group.html', locals())
            except Exception,e:
                return render(request, 'previliges/u_group.html', locals())
        elif request.POST.has_key('create'):
            try:
                info = "CREATE OK!"
                groupname = request.POST['newname']
                persetlist = request.POST.getlist('per_set')
                usersetlist = request.POST.getlist('user_set')
                s_perlist,s_userlist = pri.create_ugroup(groupname,persetlist,usersetlist)
                return render(request, 'previliges/u_group.html', locals())
            except Exception,e:
                info = "CREATE FAILED!"
                return render(request, 'previliges/u_group.html', locals())
        elif request.POST.has_key('delete'):
            try:
                groupname = request.POST['group_set']
                info = "DELETE OK!"
                pri.del_ugroup(groupname)
                return render(request, 'previliges/u_group.html', locals())
            except Exception,e:
                info = "DELETE FAILED!"
                return render(request, 'previliges/u_group.html', locals())
        elif request.POST.has_key('set'):
            try:
                info = "SET OK!"
                groupname = request.POST['group_set']
                #rename group
                new_groupname = request.POST['newname']
                if len(new_groupname)>0:
                    tmp = Group.objects.get(name=groupname)
                    tmp.name = new_groupname
                    tmp.save()
                    groupname = new_groupname
                persetlist = request.POST.getlist('per_set')
                usersetlist = request.POST.getlist('user_set')
                pri.del_ugroup(groupname)
                s_perlist, s_userlist = pri.create_ugroup(groupname, persetlist,usersetlist)
                return render(request, 'previliges/u_group.html', locals())
            except Exception,e:
                info = "SET FAILED!"
                return render(request, 'previliges/u_group.html', locals())
    else:
        pri.init_ugroup()
        return render(request, 'previliges/u_group.html', locals())


@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_set_pri', login_url='/')
def set_dbname(request):
    dblist,inslist,userlist = pri.get_fulldbname()
    acc_userlist = User.objects.all().order_by('username')
    acclist = Db_account.objects.all().order_by('tags')
    public_user = func.public_user
    if request.method == 'POST':
        if request.POST.has_key('query'):
            try:
                dbtagname = request.POST['dbtag_set']
                dbtagdt = pri.get_dbtag_detail(dbtagname)
                return render(request, 'previliges/set_dbname.html', locals())
            except Exception,e:
                return render(request, 'previliges/set_dbname.html', locals())
        elif request.POST.has_key('delete'):
            try:
                dbtagname = request.POST['dbtag_set']
                info = "DELETE OK!"
                pri.del_dbtag(dbtagname)
                return render(request, 'previliges/set_dbname.html', locals())
            except Exception,e:
                info = "DELETE FAILED!"
                return render(request, 'previliges/set_dbname.html', locals())
        elif request.POST.has_key('create'):
            try:
                info = "CREATE OK!"
                dbtagname = request.POST['newdbtag']
                newdbname = request.POST['newdbname']
                inssetlist = request.POST.getlist('dbname_set')
                usersetlist = request.POST.getlist('user_set')
                dbtagdt = pri.create_dbtag(dbtagname,newdbname,inssetlist,usersetlist)
                return render(request, 'previliges/set_dbname.html', locals())
            except Exception,e:
                info = "CREATE FAILED!"
                return render(request, 'previliges/set_dbname.html', locals())
        elif request.POST.has_key('set'):
            try:
                info = "SET OK!"
                dbtagname = request.POST['dbtag_set']
                inssetlist = request.POST.getlist('dbname_set')
                usersetlist = request.POST.getlist('user_set')

                new_dbtagname = request.POST['newdbtag']
                newdbname = request.POST['newdbname']
                dbtagdt = pri.set_dbtag(dbtagname,new_dbtagname,newdbname,inssetlist, usersetlist)
                # print dbtagdt
                return render(request, 'previliges/set_dbname.html', locals())
            except Exception,e:
                info = "SET FAILED!"
                return render(request, 'previliges/set_dbname.html', locals())


        elif request.POST.has_key('query_ins'):
            try:

                insname  = Db_instance.objects.get(id = int(request.POST['ins_set']))

                return render(request, 'previliges/set_dbname.html', locals())
            except Exception,e:
                return render(request, 'previliges/set_dbname.html', locals())

        elif request.POST.has_key('set_ins'):
            try:
                info = "SET OK!"
                insname  = Db_instance.objects.get(id = int(request.POST['ins_set']))
                insname = pri.set_ins(insname,request.POST['newinsip'],request.POST['newinsport'],request.POST['role'],request.POST['dbtype'])
                return render(request, 'previliges/set_dbname.html', locals())
            except Exception,e:
                info = "SET FAILED!"
                return render(request, 'previliges/set_dbname.html', locals())

        elif request.POST.has_key('create_ins'):
            try:
                info = "CREATE OK!"
                insname = pri.create_dbinstance(request.POST['newinsip'],request.POST['newinsport'],request.POST['role'],request.POST['dbtype'])
                return render(request, 'previliges/set_dbname.html', locals())
            except Exception,e:
                info = "CREATE FAILED!"
                return render(request, 'previliges/set_dbname.html', locals())
        elif request.POST.has_key('delete_ins'):
            try:
                insname  = Db_instance.objects.get(id = int(request.POST['ins_set']))

                info = "DELETE OK!"
                insname.delete()
                return render(request, 'previliges/set_dbname.html', locals())
            except Exception,e:
                info = "DELETE FAILED!"
                return render(request, 'previliges/set_dbname.html', locals())


        elif request.POST.has_key('query_acc'):
            try:
                account_set = Db_account.objects.get(id = int(request.POST['acc_set']))
                return render(request, 'previliges/set_dbname.html', locals())
            except Exception,e:
                return render(request, 'previliges/set_dbname.html', locals())
        elif request.POST.has_key('create_acc'):
            try:
                info = "CREATE db_account OK!"
                # dbtagname = request.POST['dbtag_set']
                account_set = pri.create_acc(request.POST['newacctag'],request.POST['newaccuser'],request.POST['newaccpawd'],request.POST.getlist('accdb_set'),request.POST.getlist('accuser_set'),request.POST['acc_role'])
                return render(request, 'previliges/set_dbname.html', locals())
            except Exception,e:
                info = "CREATE db_account FAILED!"
                return render(request, 'previliges/set_dbname.html', locals())
        elif request.POST.has_key('set_acc'):
            try:
                info = "SET db_account OK!"
                # dbtagname = request.POST['dbtag_set']
                old_account = Db_account.objects.get(id = int(request.POST['acc_set']))
                account_set = pri.set_acc(old_account,request.POST['newacctag'],request.POST['newaccuser'],request.POST['newaccpawd'],request.POST.getlist('accdb_set'),request.POST.getlist('accuser_set'),request.POST['acc_role'])
                return render(request, 'previliges/set_dbname.html', locals())
            except Exception,e:
                info = "SET db_account FAILED!"
                return render(request, 'previliges/set_dbname.html', locals())

        elif request.POST.has_key('delete_acc'):
            try:
                # dbtagname = request.POST['dbtag_set']
                account_set = Db_account.objects.get(id=int(request.POST['acc_set']))

                if account_set.mysql_monitor_set.all()[:1]:
                    info = "DELETE db_account FAILED!ACCOUNT USED FOR MONITOR"
                else:
                    info = "DELETE db_account OK!"
                    account_set.delete()
                return render(request, 'previliges/set_dbname.html', locals())
            except Exception,e:
                info = "DELETE db_account FAILED!"
                return render(request, 'previliges/set_dbname.html', locals())
        elif request.POST.has_key('encrypt'):
            pri.encrypt_passwd()
            return render(request, 'previliges/set_dbname.html', locals())
    else:
        pri.check_pubuser()
        return render(request, 'previliges/set_dbname.html', locals())


@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_set_pri', login_url='/')
def fast_dbset(request):
    inslist = Db_instance.objects.all()
    if request.method == 'POST':
        try:
            info = "CREATE OK!"
            ins_set = request.POST['ins_set']

            newinsip = request.POST['newinsip']
            newinsport = request.POST['newinsport']

            newdbtag = request.POST['newdbtag']
            newdbname = request.POST['newdbname']

            newname_all = request.POST['newname_all']
            newpass_all = request.POST['newpass_all']

            newname_admin = request.POST['newname_admin']
            newpass_admin = request.POST['newpass_admin']
            newdbtype = request.POST['dbtype']
            # print newname_all
            # print "what the fuck"
            info = pri.createdb_fast(ins_set,newinsip,newinsport,newdbtag,newdbname,newname_all,newpass_all,newname_admin,newpass_admin,newdbtype)

            return render(request, 'previliges/fast_dbset.html', locals())
        except Exception,e:
            info = "CREATE FAILED!"
            return render(request, 'previliges/fast_dbset.html', locals())
    else:
        pri.check_pubuser()
        return render(request, 'previliges/fast_dbset.html', locals())


#table structure
@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_see_metadata', login_url='/')
def meta_data(request):
    try:
        favword = request.COOKIES['myfavword']
    except Exception,e:
        pass
    objlist = func.get_mysql_hostlist(request.user.username, 'meta')  # host_list = [dbtag, dbtag]
    if request.method == 'POST':
        try:
            choosed_host = request.POST['cx']
            table_se = request.POST['searchname']
            if request.POST.has_key('query'):
                (data_list, collist, dbname) = meta.get_metadata(choosed_host,1)
                #print("....",data_list, collist, dbname)
                return render(request, 'meta_data.html', locals())
            elif request.POST.has_key('structure'):
                tbname = request.POST['structure'].split(';')[0]
                (field, col, dbname) = meta.get_metadata(choosed_host,2,tbname)
                (ind_data, ind_col, dbname) = meta.get_metadata(choosed_host, 3, tbname)
                (tbst, tbst_col, dbname) = meta.get_metadata(choosed_host, 4, tbname)
                (sh_cre, sh_cre_col, dbname) = meta.get_metadata(choosed_host, 5, tbname)

                return render(request, 'meta_data.html', locals())
            elif request.POST.has_key('search'):
                print table_se
                (data_list, collist, dbname) = meta.get_metadata(choosed_host, 1,table_se)
                return render(request, 'meta_data.html', locals())
        except Exception,e:
            return render(request, 'meta_data.html', locals())
    else:
        return render(request, 'meta_data.html', locals())


@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_see_mysqladmin', login_url='/')
def mysql_admin(request):
    inslist = Db_instance.objects.filter(db_type='mysql').order_by("ip")
    if request.method == 'POST':
        try:
            selfsql = request.POST['selfsql'].strip()
            insname = Db_instance.objects.get(id=int(request.POST['ins_set']))
            tmpli = []
            for i in insname.db_name_set.all():
                for x in i.instance.all():
                    tmpli.append(int(x.id))
            tmpli = list(set(tmpli))
            bro = Db_instance.objects.filter(id__in=tmpli)

            if request.POST.has_key('fullpro'):
                data_list, collist = meta.process(insname)
                return render(request, 'admin/mysql_admin.html', locals())

            elif  request.POST.has_key('showactive'):
                data_list, collist = meta.process(insname,2)
                return render(request, 'admin/mysql_admin.html', locals())

            elif request.POST.has_key('showengine'):
                datalist, col = meta.process(insname, 3)
                return render(request, 'admin/mysql_admin.html', locals())

            elif request.POST.has_key('kill_list'):
                idlist = request.POST.getlist('choosedlist')
                tmpstr=''
                for i in idlist:
                    tmpstr= tmpstr + 'kill ' + i +';'
                datalist, col = meta.process(insname, 4,tmpstr)
                return render(request, 'admin/mysql_admin.html', locals())

            elif request.POST.has_key('showmutex'):
                datalist, col = meta.process(insname, 5)
                return render(request, 'admin/mysql_admin.html', locals())
            elif request.POST.has_key('showbigtb'):
                datalist, col = meta.process(insname, 6)
                return render(request, 'admin/mysql_admin.html', locals())

            elif request.POST.has_key('showstatus'):
                vir = request.POST['variables'].strip()
                sql = "show global status like '%" + vir +"%'"
                datalist, col = meta.process(insname, 7,sql)
                return render(request, 'admin/mysql_admin.html', locals())
            elif request.POST.has_key('showinc'):
                datalist, col = meta.process(insname, 8)
                return render(request, 'admin/mysql_admin.html', locals())
            elif request.POST.has_key('showvari'):
                vir = request.POST['variables'].strip()
                sql = "show global variables like '%" + vir + "%'"
                datalist, col = meta.process(insname, 7,sql)
                return render(request, 'admin/mysql_admin.html', locals())
            elif request.POST.has_key('slavestatus'):
                sql = "show slave status"
                datalist, col = meta.process(insname, 7,sql)
                return render(request, 'admin/mysql_admin.html', locals())
            elif request.POST.has_key('search'):
                vir = request.POST['variables'].strip()
                a = Db_instance.objects.filter(ip__icontains=vir)
                bro =''
                if a:
                    inslist = a
                else:
                    info = "IP NOT FOUND"
                return render(request, 'admin/mysql_admin.html', locals())
            elif request.POST.has_key('execute'):
                bro = ''
                datalist, col = meta.process(insname, 7, meta.check_selfsql(selfsql))
                return render(request, 'admin/mysql_admin.html', locals())
        except Exception,e:

            return render(request, 'admin/mysql_admin.html', locals())
    else:
        return render(request, 'admin/mysql_admin.html', locals())


@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_see_mysqladmin', login_url='/')
def tb_check(request):
    objlist = func.get_mysql_hostlist(request.user.username, 'meta')
    if request.method == 'POST':
        choosed_host = request.POST['choosed']
        if request.POST.has_key('bigtb'):
            data_list,collist = meta.get_his_meta(choosed_host,1)
        elif request.POST.has_key('auto_occ'):
            data_list, collist = meta.get_his_meta(choosed_host,2)
        elif request.POST.has_key('tb_incre'):
            data_list, collist = meta.get_his_meta(choosed_host,3)
        elif request.POST.has_key('db_sz'):
            data_list, collist = meta.get_his_meta(choosed_host, 4)
        elif request.POST.has_key('db_inc'):
            data_list, collist = meta.get_his_meta(choosed_host, 5)
        return render(request, 'admin/tb_check.html', locals())

    else:
        return render(request, 'admin/tb_check.html', locals())

@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_see_mysqladmin', login_url='/')
def dupkey_check(request):
    # ins_li=get_dupreport_all()
    # print ins_li
    objlist = func.get_mysql_hostlist(request.user.username, 'meta')   # read/all/write role instance
    if request.method == 'POST':
        choosed_host = request.POST['choosed']
        if request.POST.has_key('dupkey'):
            dupkey_result = get_dupreport(choosed_host)
        elif request.POST.has_key('dupkey_mail'):
            get_dupreport.delay(choosed_host,request.user.email)
            info = "mail send,check your email later"
    return render(request, 'admin/dupkey_check.html', locals())



@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_see_mysqladmin', login_url='/')
def mysql_binlog_parse(request):
    inslist = Db_instance.objects.filter(db_type='mysql').order_by("ip")
    if request.method == 'POST':
        try:
            binlist = []
            dblist = []
            insname = Db_instance.objects.get(id=int(request.POST['ins_set']))
            datalist, col = meta.get_process_data(insname, 'show binary logs')
            dbresult, col = meta.get_process_data(insname, 'show databases')
            if col != ['error']:
                for i in datalist:
                    binlist.append(i[0])
                for i in dbresult:
                    dblist.append(i[0])
            else:
                del binlist
                return render(request, 'admin/binlog_parse.html', locals())
            if request.POST.has_key('show_binary'):
                return render(request, 'admin/binlog_parse.html', locals())
            elif request.POST.has_key('parse'):
                binname = request.POST['binary_list']
                countnum = int(request.POST['countnum'])
                if countnum not in [10,50,200]:
                    countnum = 10
                # print countnum
                begintime = request.POST['begin_time']
                tbname = request.POST['tbname']
                dbselected = request.POST['dblist']
                parse_binlog.delay(insname, binname, begintime, tbname, dbselected,request.user.username,countnum,False)
                info = "Binlog REDO Parse mission uploaded"
            elif request.POST.has_key('parse_first'):
                binname = request.POST['binary_list']
                sqllist = parse_binlogfirst(insname, binname, 5)
            elif request.POST.has_key('parse_undo'):
                binname = request.POST['binary_list']
                countnum = int(request.POST['countnum'])
                if countnum not in [10, 50, 200]:
                    countnum = 10
                begintime = request.POST['begin_time']
                tbname = request.POST['tbname']
                dbselected = request.POST['dblist']
                parse_binlog.delay(insname, binname, begintime, tbname, dbselected, request.user.username, countnum,True)
                info = "Binlog UNDO Parse mission uploaded"
        except Exception,e:
            pass
        return render(request, 'admin/binlog_parse.html', locals())
    else:
        return render(request, 'admin/binlog_parse.html', locals())

@login_required(login_url='/accounts/login/')
def pass_reset(request):
    if request.method == 'POST':
        try:
        # newpasswd = request.POST['passwd'].strip()
            tmp = User.objects.get(username=request.user.username)
            p = request.POST['passwd'].strip()
            tmp.set_password(p)
            tmp.save()
            info = "reset passwd ok"
            # save pwd
            try:
                u = User.objects.get(username=request.user.username)
                user_pwd=Db_user_pwd.objects.filter(user=u)
                if len(user_pwd) > 0:
                    update_user_pwd = Db_user_pwd.objects.get(user=u)
                    update_user_pwd.pwd = p
                    update_user_pwd.save()
                else:
                    newpwd = Db_user_pwd(user=u,pwd=str(p))
                    newpwd.save()
            except Exception as e:
                print("change pwd save failed {}".format(str(e)))
            # save pwd done
            return render(request, 'previliges/pass_reset.html', locals())
        except:
            info = "reset passwd failed"
            return render(request, 'previliges/pass_reset.html', locals())
    else:
        return render(request, 'previliges/pass_reset.html', locals())


@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_see_metadata', login_url='/')
def get_tblist(request):
    choosed_host = request.GET['dbtag'].split(';')[0]
    if len(choosed_host) >0 and choosed_host in func.get_mysql_hostlist(request.user.username, 'meta'):
        tblist = map(lambda x:x[0],meta.get_metadata(choosed_host, 6))
    else :
        tblist = ['wrong dbname',]
    return HttpResponse(json.dumps(tblist), content_type='application/json')

@login_required(login_url='/accounts/login/')
@permission_required('myapp.can_see_metadata', login_url='/')
def diff(request):
    objlist = func.get_mysql_hostlist(request.user.username, 'meta')
    # result = func.get_diff('mysql-lepus-test','mysql_replication','mysql-lepus','mysql_replication')
    # print result
    if request.method == 'POST':
        if  request.POST.has_key('check'):
            choosed_host1 = request.POST['choosedb1'].split(';')[0]
            choosed_host2 = request.POST['choosedb2'].split(';')[0]
            choosed_tb1 = request.POST['choosetb1'].split(';')[0]
            choosed_tb2 = request.POST['choosetb2'].split(';')[0]
            if choosed_host1 in objlist and choosed_host2 in objlist:
                result = func.get_diff(choosed_host1, choosed_tb1, choosed_host2, choosed_tb2)
                (sh_cre1, sh_cre_col, dbname) = meta.get_metadata(choosed_host1, 5, choosed_tb1)
                (sh_cre2, sh_cre_col, dbname) = meta.get_metadata(choosed_host2, 5, choosed_tb2)
    return render(request,'diff.html', locals())






# @ratelimit(key=func.my_key, rate='5/h')
# def test(request):
#     try:
#         xaxis = []
#         yaxis = []
#         choosed_host = request.GET['dbtag']
#         days_before = int(request.GET['day'])
#         if days_before not in [7,15,30]:
#             days_before = 7
#         if choosed_host!='all':
#             data_list, col = meta.get_hist_dbinfo(choosed_host,days_before)
#         elif choosed_host == 'all':
#             return JsonResponse({'xaxis': ['not support all'], 'yaxis': [1]})
#         for i in data_list:
#             xaxis.append(i[0])
#             yaxis.append(i[1])
#         mydata = {'xaxis':xaxis,'yaxis':yaxis}
#     except Exception,e:
#         print e
#         mydata = {'xaxis': ['error'], 'yaxis': [1]}
#     return JsonResponse(mydata)
#
#
# def tb_inc_status(request):
#     xaxis7 = []
#     yaxis7 = []
#     xaxis15 = []
#     yaxis15 = []
#     xaxis30 = []
#     yaxis30 = []
#     choosed_host = request.GET['dbtag']
#     tbname = request.GET['tbname'].strip()
#     print choosed_host
#     print tbname
#     print len(tbname)
#     data_list7, col7 = meta.get_hist_tbinfo(choosed_host,tbname,7)
#     data_list15,col15 = meta.get_hist_tbinfo(choosed_host,tbname,15)
#     data_list30, col30 = meta.get_hist_tbinfo(choosed_host, tbname, 30)
#     for i in data_list7:
#         xaxis7.append(i[0])
#         yaxis7.append(i[1])
#     for i in data_list15:
#         xaxis15.append(i[0])
#         yaxis15.append(i[1])
#     for i in data_list30:
#         xaxis30.append(i[0])
#         yaxis30.append(i[1])
#     return JsonResponse({'xaxis7': xaxis7, 'yaxis7': yaxis7,'xaxis15': xaxis15, 'yaxis15': yaxis15,'xaxis30': xaxis30, 'yaxis30': yaxis30})