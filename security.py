import os
import re
import json
import sys
import threading
import time
import logging
import string
import random
from typing import Optional
import hashlib
import smtplib
import requests
import ldap3
import ssl
import uvicorn
from ldap3 import Tls
from dotenv import load_dotenv
from ldap3.core.exceptions import LDAPException
from ldap3.extend.microsoft.modifyPassword import ad_modify_password
from ldap3.extend.microsoft.unlockAccount import ad_unlock_account
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups
from ldap3.extend.microsoft.removeMembersFromGroups import ad_remove_members_from_groups
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from logging.handlers import RotatingFileHandler
from fastapi.responses import JSONResponse
from fastapi.security.api_key import APIKeyHeader
from fastapi import FastAPI, Request, HTTPException, Depends, Security
import smtplib
from send_mail import SendMail

class Secure(SendMail):    
    
    def rand_token_passwd(self,length=6):
        if length <= 10:
            characters = string.ascii_letters + string.digits
        else: 
            characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))
    
    def encrypt_token(self,option: str | None):
        # Create a SHA256 hash object
        sha256_hash = hashlib.sha256()
        if option is None:
            tkn = self.rand_token_passwd(6)
            # Update the hash object with the bytes of the string
            self.smtpsendtoken(tkn)
            sha256_hash.update(tkn.encode('utf-8'))
            del tkn
        else:
            sha256_hash.update(option.encode('utf-8'))
        # Return the hexadecimal digest of the hash
        return sha256_hash.hexdigest()

    def auth_tkn(self):
        rcv_tkn = str(input('Điền token bạn nhận được ở mail: '))
        return self.encrypt_token(rcv_tkn)



def generate_random_key(length=10):
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))

def vigenere_cipher(text, key, mode='encode'):
    key = [ord(k) - 65 for k in key.upper()]
    key_length = len(key)
    processed_text = []
    key_index = 0

    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            char_code = ord(char) - offset
            if mode == 'encode':
                char_code = (char_code + key[key_index % key_length]) % 26
            elif mode == 'decode':
                char_code = (char_code - key[key_index % key_length] + 26) % 26
            processed_text.append(chr(char_code + offset))
            key_index += 1
        else:
            processed_text.append(char)

    return ''.join(processed_text)

def main():
    while True:
        print("Vigenere Cipher Tool")
        print("1. Encode")
        print("2. Decode")
        print("3. Generate Random Key")
        print("4. Quit")

        choice = input("Enter your choice: ")

        if choice == '1':
            text = input("Enter text to encode: ")
            key = input("Enter key: ")
            encoded_text = vigenere_cipher(text, key, mode='encode')
            print(f"Encoded text: {encoded_text}")

        elif choice == '2':
            text = input("Enter text to decode: ")
            key = input("Enter key: ")
            decoded_text = vigenere_cipher(text, key, mode='decode')
            print(f"Decoded text: {decoded_text}")

        elif choice == '3':
            length = int(input("Enter length of random key: "))
            random_key = generate_random_key(length)
            print(f"Generated random key: {random_key}")

        elif choice == '4':
            break

        else:
            print("Invalid choice. Please try again.")