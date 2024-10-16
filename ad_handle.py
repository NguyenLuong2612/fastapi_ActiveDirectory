import os
import re
import json
import sys
import threading
import time
import logging
import string
import random
import hashlib
import smtplib
import requests
import ldap3
import ssl
import uvicorn
from ldap3 import Tls, MODIFY_REPLACE
from dotenv import load_dotenv
import ldap3.extend.microsoft.modifyPassword
import ldap3.extend.microsoft.unlockAccount  
import ldap3.extend.microsoft.addMembersToGroups
import ldap3.extend.microsoft.removeMembersFromGroups  
from ldap3.core.exceptions import LDAPException
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from logging.handlers import RotatingFileHandler
from fastapi.responses import JSONResponse
from fastapi.security.api_key import APIKeyHeader
from fastapi import FastAPI, Request, HTTPException, Depends, Security
import smtplib
from security import Secure


class AD_Handle(Secure):

    def __init__(self,USER: str,PASSWD: str):
        self.LDAP_HOST = "10.128.10.131"
        self.LDAP_USER = 'luongnv'
        self.LDAP_PASSWD = 'admin@123'
        self.OU = "OU=Mail,"
        self.LDAP_BASE_DN = "DC=staging,DC=fpt,DC=net"
        self.OBJECT_CLASS = ['person', 'organizationalPerson', 'user']
        self._USER = USER
        self._PASSWD = PASSWD
        
    def ldap_server(self):
        return ldap3.Server(self.LDAP_HOST)

    def ldap_login(self):
        try:
            # Thực hiện kết nối đến LDAP server
            conn = ldap3.Connection(
                self.ldap_server(),
                user=self._USER,
                password=self._PASSWD,
                auto_bind=True  # Kết nối và xác thực tự động
            )
            print("Kết nối LDAP thành công.")
            return conn  # Trả về đối tượng kết nối nếu thành công

        except ldap3.core.exceptions.LDAPBindError:
            # Xử lý lỗi nếu xác thực không thành công
            print("Lỗi: Thông tin tài khoản người dùng không hợp lệ.")
            return None  # Trả về None hoặc một giá trị báo lỗi

        except Exception as e:
            # Xử lý tất cả các lỗi khác
            print(f"Lỗi khi kết nối tới LDAP: {e}")
            return None

    def ldap_connection(self):
        try:
            # Thực hiện kết nối đến LDAP server
            conn = ldap3.Connection(
                self.ldap_server(),
                user=self.LDAP_USER,
                password=self.LDAP_PASSWD,
                auto_bind=True  # Kết nối và xác thực tự động
            )
            return conn

        except ldap3.core.exceptions.LDAPBindError:
            # Xử lý lỗi nếu xác thực không thành công
            print("Lỗi: Thông tin tài khoản quản trị viên không hợp lệ.")
            return None  # Trả về None hoặc một giá trị báo lỗi

        except Exception as e:
            # Xử lý tất cả các lỗi khác
            print(f"Lỗi khi kết nối tới LDAP: {e}")
            return None
        
    def ldap_connect_tkn(self, conn_login: ldap_login, conn: ldap_connection):
        if conn_login is not None:
            encrypt = self.encrypt_token(None)
            count = 3
            while True:
                count -= 1
                
                if encrypt == self.auth_tkn():
                    return conn

                elif count <= 0:
                    ##  timeout 5-10p logout khi quá 3 lần
                    
                    print('Logout')
                    
                    return not conn.unbind()
                
                else:
                    print(f'Nhập lại token (số lần được nhập còn {count})')
        else:
            return False


    async def find_ad_users(self, conn, user_dn: str):
        conn.search(
            search_base = self.LDAP_BASE_DN,
            search_filter = f"(userPrincipalName={user_dn})",
            search_scope = ldap3.SUBTREE,
            attributes = ldap3.ALL_ATTRIBUTES,
            get_operational_attributes = True,
        )
        return json.loads(conn.response_to_json())
    
    def natural_key(self,s: str):
        username = s.split('@')[0]
        dn = s.split('@')[1]
        # Sử dụng biểu thức chính quy để tách phần chữ và số ở cuối chuỗi
        match = re.match(r'([a-zA-Z]+)(\d+)$', username)
        if match:
            # Trả về mảng chứa phần chữ và phần số
            return match.group(1), int(match.group(2)), dn
        else:
            return username, 0, dn
    
    def chk_PrincipalName(self, conn, user_dn: str):
        conn.search(
            search_base = self.LDAP_BASE_DN,
            search_filter = f"(userPrincipalName={user_dn})",
            search_scope = ldap3.SUBTREE,
            attributes = ldap3.ALL_ATTRIBUTES,
            get_operational_attributes = True,
        )
        result = conn.entries
        return True if not result else False

    def getAttribute(self,name: str, usr: str, num: int ,dn: str, department: str):
        gvname, sn = ' '.join(name.split(' ')[:-1]), name.split(' ')[-1]
        usr = usr if num == 0 else usr + str(num)
        
        return {
            "displayName": name,
            "sAMAccountName": usr,
            "userPrincipalName": "{0}@{1}".format(usr,dn),
            "name": name,
            "givenName": gvname,
            "sn": sn,
            'department':  department
        }

    def create_usr(self,conn, user, ou: str):
        usr, num, dn = self.natural_key(user.user_dn)    # user  1  domain
        name = user.ho.title() + ' ' + user.ten.title()
        distName = f'CN={user.cmnd},{ou + self.LDAP_BASE_DN}'
        
        attributes = self.getAttribute(name, usr,num, dn, user.department)
        print(attributes)  # check attribute (cmt khi dùng xong)
        
        while self.chk_PrincipalName(conn, user.user_dn):
            result = conn.add(dn= distName,
                        object_class=self.OBJECT_CLASS,
                        attributes=attributes)
            print(f'Create {user.user_dn}')
            if not result:
                msg = "ERROR: User '{0}' was not created: {1}".format(
                    name, conn.result.get("description"))
                raise Exception(msg)
            conn.extend.microsoft.unlock_account(user=user.user_dn)
            passwd = self.rand_token_passwd(6)
            # conn.extend.microsoft.modify_password(user=user.user_dn,
            #                             new_password=self.rand_token_passwd(16),
            #                             old_password=None)
            conn.extend.microsoft.modify_password(distName, passwd, old_password=None)
            # ldap3.extend.microsoft.modifyPassword.ad_modify_password(conn, user.user_dn, passwd, old_password=None)
            print(passwd)
            pwd_expire = {"pwdLastSet": (ldap3.MODIFY_REPLACE, [0])}
            conn.modify(distName, changes=pwd_expire)
            conn.modify(distName, {'userAccountControl': [('MODIFY_REPLACE', 512)]})
            return
        else:
            num = num + 1
            user.user_dn = f'{usr}{num}@{dn}'
            return self.create_usr(conn, user, ou)
        
