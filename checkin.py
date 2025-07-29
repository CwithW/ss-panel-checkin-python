import requests
import json
import logging
import urllib3
import hashlib
import os
import traceback
import re

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Checkin:
    def __init__(self, host, email, passwd,insecure=False):
        if not host or not email or not passwd:
            raise ValueError("Missing argument")
        self.host = host
        self.email = email
        self.passwd = passwd
        self.session = requests.Session()
        self.session.headers.update({"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0"})
        self.session.verify = not insecure
    def get_csrf(self):
        url = f"{self.host}/auth/login"
        resp = self.session.get(url)
        if not "PHPSESSID" in resp.cookies: # no session means no csrf
            logger.info("CSRF token not found, no session established")
            return False
        # <input type="hidden" name="csrf_token" value="2WC0Df0RkADO8MKxy3TRLvuFtgQZa1BCiTmUEVRnarcnUCVKtOtZt82dRBcj8DUv">
        regex_for_csrf_token = r'<input type="hidden" name="csrf_token" value="([^"]+)">'
        csrf_token = re.search(regex_for_csrf_token, resp.text)
        if csrf_token:
            csrf_token = csrf_token.group(1)
            logger.info(f"CSRF token found: {csrf_token}")
            return csrf_token
        logger.info("CSRF token not found in the response")
        return False
    def login(self):
        url = f"{self.host}/auth/login"
        data = {
            "email": self.email,
            "passwd": self.passwd,
            "remember_me":"week",
        }
        csrf_token = self.get_csrf()
        if csrf_token:
            data["csrf_token"] = csrf_token
        try:
            resp = self.session.post(url, data=data)
            if resp.status_code != 200:
                raise Exception(f"Login API {resp.status_code}: {resp.text}")
            login_resp = resp.json()
            if login_resp.get("ret") != 1:
                raise Exception(f"Login failed: {str(login_resp)}")
            logger.info("Login successful")
            return True
        except Exception as e:
            logger.error(traceback.format_exc())
            return False

    def is_login(self):
        url = f"{self.host}/user"
        try:
            resp = self.session.get(url, allow_redirects=False)
            if resp.status_code == 200:
                return True
            elif resp.status_code == 302 and "login" in resp.headers.get("Location", ""):
                return False
            else:
                logger.warning(f"Unexpected status code {resp.status_code} for is_login check")
                return False
        except Exception as e:
            logger.error(f"Error checking login status: {str(e)}")
            return False

    def handle(self):
        if not self.is_login():
            self.session.cookies.clear()  # Clear cookies if not logged in
            logger.info("Not logged in, attempting to login...")
            if not self.login():
                logger.error("Login failed, cannot proceed with checkin")
                return False
        else:
            logger.info("Already logged in, proceeding with checkin")
        return self.checkin()
    def checkin(self):
        url = f"{self.host}/user/checkin"
        try:
            resp = self.session.post(url)
            if resp.status_code != 200:
                raise Exception(f"Checkin API {resp.status_code}: {resp.text}")
            checkin_resp = resp.json()
            logger.info(checkin_resp.get("msg", "No message"))
            return True
        except Exception as e:
            logger.error(traceback.format_exc())
            return False
    
    def __default_session_file(self):
        hashkey = hashlib.md5(f"{self.host}{self.email}".encode()).hexdigest()
        return f"./session/session_{hashkey}.json"

    def save_session(self,session_file=None):
        if session_file is None:
            session_file = self.__default_session_file()
        try:
            with open(session_file, 'w') as f:
                json.dump(self.session.cookies.get_dict(), f)
            logger.info(f"Session saved to {session_file}")
        except Exception as e:
            logger.error(f"Failed to save session: {str(e)}")
    
    def load_session(self, session_file=None):
        if session_file is None:
            session_file = self.__default_session_file()
        if not os.path.exists(session_file):
            return False
        try:
            with open(session_file, 'r') as f:
                cookies = json.load(f)
                self.session.cookies.update(cookies)
            logger.info(f"Session loaded from {session_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to load session: {str(e)}")
            return False