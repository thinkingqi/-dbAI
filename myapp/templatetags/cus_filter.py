#!/usr/bin/env python
#-*- coding:utf8 -*-
"""
@author: qihengshan
@software: PyCharm
@time: 2017/12/5 09:11
"""
from itertools import cycle
from django import template
import datetime
from myapp.include.encrypt import prpcrypt
register = template.Library()


@register.filter
def descrypt(values):
    py = prpcrypt()
    values = py.decrypt(values)
    return values


@register.filter
def s_to_d(values):
    values = int(values/3600/24)
    return str(values)+'d'

@register.filter
def adjtime(values):
    values = values-datetime.timedelta(hours=8)
    return values


@register.filter
def exact_columns(items, number_of_columns):
    """Divides a list in an exact number of columns.
    The number of columns is guaranteed.

    Examples:

        8x3:
        [[1, 2, 3], [4, 5, 6], [7, 8]]

        2x3:
        [[1], [2], []]
    """
    try:
        number_of_columns = int(number_of_columns)
        items = list(items)
    except (ValueError, TypeError):
        return [items]

    columns = [[] for x in range(number_of_columns)]
    actual_column = cycle(range(number_of_columns))
    for item in items:
        columns[actual_column.next()].append(item)

    return columns

@register.filter
def split_cols(string):
    """
    Return the string split by sep.
    Example usage: {{ value|split:","}}
    """
    #string.replace(',', ',\n')
    a = [i.strip() for i in string.split(',') if len(i.strip()) >0]
    return ',\n'.join(a)