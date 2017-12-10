#!/usr/bin/env python
#-*- coding:utf8 -*-
#__author__:'戚恒山'
"""
@version: ??
@author: qihengshan
@software: PyCharm
@file: mylib.py
@time: 2017/12/4 20:26
"""

#from _mysql import escape_string
from  MySQLdb import escape_string
import MySQLdb


def escape(sql):

    if sql is None:
        return ''
    if not isinstance(sql, (basestring, unicode)):
        return sql
    try:
        if isinstance(sql, unicode):
            sql = sql.encode('utf8')
    except Exception:
        pass
    return escape_string(sql)


class DBTool():

    def __init__(self, username=None, host=None, port=None, database=None, password=None):
        self.username = username
        self.host = host
        self.port = port
        self.database = database
        self.password = password
        self.charset = "utf8"

    def _gen_connection(self):

        return MySQLdb.connect(host=self.host, db=self.database, user=self.username, passwd=self.password, port=self.port, charset=self.charset)

    def query(self, sql, query_param=None):
        """
            查询数据库获取返回， 返回的结果集为dict形式， 如果数据库错误， 返回NONE
        """
        conn = None
        cursor = None
        try:
            conn = self._gen_connection()
            cursor = conn.cursor(cursorclass = MySQLdb.cursors.DictCursor)
            cursor.execute(sql, query_param)
            result_set = cursor.fetchall()
            conn.commit()
            return result_set
        except:
            return None
        finally:
            try:
                if cursor:
                    cursor.close()
                if conn:
                    conn.close()
            except:
                pass

    def execute(self, sql, execute_param=None):

        conn = None
        cursor = None

        try:
            conn = self._gen_connection()
            cursor = conn.cursor()
            row_fettch = cursor.execute(sql, execute_param)
            conn.commit()
            return row_fettch
        except:
            return -1
        finally:
            try:
                if cursor:
                    cursor.close()
                if conn:
                    conn.close()
            except:
                pass

    def query2(self, sql, query_param=None):
        """
            查询数据库获取返回， 返回的结果集为dict形式， 如果数据库错误， 返回NONE
        """
        conn = None
        cursor = None
        try:
            conn = self._gen_connection()
            cursor = conn.cursor()
            cursor.execute(sql, query_param)
            result_set = cursor.fetchall()
            conn.commit()
            return result_set
        except:
            return None
        finally:
            try:
                if cursor:
                    cursor.close()
                if conn:
                    conn.close()
            except:
                pass
