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
from ldap3 import Tls
from dotenv import load_dotenv
from ldap3.core.exceptions import LDAPException
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from logging.handlers import RotatingFileHandler
from fastapi.responses import JSONResponse
from fastapi.security.api_key import APIKeyHeader
from fastapi import FastAPI, Request, HTTPException, Depends, Security
import smtplib


class SendMail:

    def smtpsendtoken(self,context: str | int):
        port = 465  # For SSL
        smtp_server = "smtp.gmail.com"
        sender_email = "lomki12231@gmail.com"
        receiver_email = "nguyenluong0203@outlook.com.vn"
        password = "xvhw nlyh kpwm weev"
        subject = "Token của bạn"
        body = context

        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
