# -*- coding: UTF-8 -*-
from collections import defaultdict, OrderedDict
from func.SqlChecker import SqlChecker
import re
import sys
import logging
import argparse

sys.dont_write_bytecode = True

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s", datefmt='\033[00;34m%H:%M:%S\033[0m'
)

parser = argparse.ArgumentParser(usage='python %(prog)s [options]', description='PassiveSqlCheck for bool-based and time-based', add_help=False)
parser.add_argument('--help', action="store_true", help='for help')
parser.add_argument('-f', '--file',default="xml/burp.xml", help='The burp http history data. default: "xml/burp.xml"')
parser.add_argument('-h', '--host', default=[], nargs="*", help='The domain name to be detected. (e.g: *.test.com  or  test.com)')
parser.add_argument('--level', default=1, type=int, help='level 1 will test ` ` and `\'`. level 2 will test all types. e.g: \' \') \')) " ") ...')
args = parser.parse_args()

if args.help:
    print parser.print_help()
    exit()

# 判断延迟的时间
TIMEOUT = 5

# 注入标记 使用#号可能有问题
SQLMARK = "@@"

# Regular expression used for detecting multipart POST data
MULTIPART_REGEX = "(?i)Content-Disposition:[^;]+;\s*name="

# Regular expression used for detecting JSON POST data
JSON_REGEX = r'(?s)\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]*"|\d+|true|false|null).*\}\s*(\]\s*)*\Z'

# Regular expression for XML POST data
XML_REGEX = r"(?s)\A\s*<[^>]+>(.+>)?\s*\Z"

# DBMS ERROR XML
ERROR_DBMS_XML = "xml/errors.xml"

# PAYLOADS XML
PAYLOADS_XML = "xml/payloads.xml"

# 垃圾参数列表，过滤不需要注入的参数用，如token、时间等
GARBAGE_PARAM = []

# sql注入的信息都在g_sql_info里面
g_sql_info = SqlChecker()
