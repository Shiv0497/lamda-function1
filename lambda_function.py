import json
import boto3
import config
from http.server import BaseHTTPRequestHandler, HTTPServer

from config import (
    MOODLE_PROTOCOL,
    MOODLE_URL,
    MOODLE_LOGIN_URL,
    MOODLE_TOKEN,
    MOODLE_LOGIN_TOKEN,
    REDIRECTION,
    WEBSITE_URL
)

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Login_table')

import urllib.parse
import urllib.request
from http.cookies import SimpleCookie

import os
# import bcrypt
from boto3.dynamodb.conditions import Key
# from passlib.hash import pbkdf2_sha256
# import hashlib
import os

def hash_password(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return salt.hex() + ":" + pwd_hash.hex()

def verify_password(password, hashed):
    salt_hex, hash_hex = hashed.split(":")
    salt = bytes.fromhex(salt_hex)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return pwd_hash.hex() == hash_hex

def dynamodb_login(email,password):
    res = table.get_item(Key={ "useremail": email })
    user = res.get("Item")
    if user and user["password"] == password:
        return respond(200, json.dumps({
            "message": "User Logged In Successfull!",
            "response_body": user,
            "status" : "200"
        }))
    return respond(200, json.dumps({
            "message": "User Logged In Failed!",
            "response_body": user,
            "status" : "401"
        }))
        
def do_GET(self):
        remember_token = "Njk2YzFhYzRkNDg1MzExMGY0NTZmYzMx"  # your token value

        self.send_response(200)
        self.send_header('Set-Cookie', f'rememberme={remember_token}; Path=/; Max-Age=2592000')  # 30 days
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

        self.wfile.write(b'Cookie set successfully.')

def proxy_login( email, password, platform, provider):   
    base_url = "https://awsdev.quiklrn.com/user/login.php"
    params = {
        "platform": platform,
        "email": email,
        "password": password,
        "provider": provider
    }

    query_string = urllib.parse.urlencode(params)
    full_url = f"{base_url}?{query_string}"
    try:
        req = urllib.request.Request(full_url, method="POST")
        
        with urllib.request.urlopen(req) as res:
            headers = res.info()
            body = res.read().decode("utf-8")

         # Parse cookies
        cookies = {}
        set_cookie = headers.get_all('Set-Cookie')
        if set_cookie:
            for cookie_str in set_cookie:
                cookie = SimpleCookie()
                cookie.load(cookie_str)
                for key, morsel in cookie.items():
                    cookies[key] = morsel.value

        # Parse JSON response
        try:
            data = json.loads(body)
        except Exception:
            return respond(500, json.dumps({ "message": "Invalid JSON from login server" }))
        # email = data.get("response_body", {}).get("email")
       
        from urllib import request, error, parse

        if REDIRECTION == 2:   #moodle redirection
            # email = email
            token = MOODLE_LOGIN_TOKEN
            domainname = f"{MOODLE_PROTOCOL}{MOODLE_LOGIN_URL}"
            functionname = "auth_userkey_request_login_url"

            params_moodle = {
                'wstoken': token,
                'wsfunction': functionname,
                'moodlewsrestformat': 'json',
                'user[email]': email
            }

            ws_url = f"{domainname}/lmsdev2/webservice/rest/server.php"
            query_string = parse.urlencode(params_moodle)
            full_url = ws_url + '?' + query_string

            try:
                req = request.Request(full_url, method="POST")
                with request.urlopen(req, timeout=10) as res:
                    body = res.read().decode()
                    data = json.loads(body)
            except error.HTTPError as e:
                print("HTTP error:", e.code, e.reason)
                return respond(500, json.dumps({"message": f"HTTP error: {e.code} {e.reason}"}))
            except error.URLError as e:
                print("URL error:", e.reason)
                return respond(500, json.dumps({"message": f"URL error: {e.reason}"}))

            loginurl = data.get('loginurl') or f"https://{WEBSITE_URL}"
            return respond(200, json.dumps({
                "message": "User Logged In Successful!",
                "redirect": loginurl,
                "status" : 200
            }))

        if REDIRECTION == 1: #quiklrn redirection
            if "user_id" in data:
                return respond(200, json.dumps({
                    "message": "User Logged In Successful!",
                    "response_body": data,
                    "email": email,
                    "status" : 200,
                    "rememberme": cookies.get("rememberme"),
                    "redirect": f"https://awsdev.quiklrn.com/?rememberme={cookies.get("rememberme")}"
                }))

        if REDIRECTION == 3:  #quiz redirection
            if "user_id" in data:
                return respond(200, json.dumps({
                    "message": "User Logged In Successful!",
                    "response_body": data,
                    "email": email,
                    "status" : 200,
                    "rememberme": cookies.get("rememberme"),
                    # "redirect":f"https://enrollment-dev.quiklrn.com/quiz_player.php?qquiz_url=https://awsdev.quiklrn.com/user/cloud.php?method=download_public&cloud_repository_id=470&auth_code={cookies.get("rememberme")}"
                    # "redirect": f"https://enrollment-dev.quiklrn.com/quiz_player.php?qquiz_url=https%3A%2F%2Fawsdev.quiklrn.com%2Fuser%2Fcloud.php%3Fmethod%3Ddownload_public%26cloud_repository_id%3D470%26auth_code={cookies.get("rememberme")}"
                    # "redirect" : f"https://enrollment-dev.quiklrn.com/quiz_player.php?qquiz_url=https://awsdev.quiklrn.com/user/cloud.php?method=download_public&cloud_repository_id=470&auth=c85a3762c06ebd03cf247d18403eb3ea&auth_code={cookies.get("rememberme")}"
                        "redirect" : f"https://enrollment-dev.quiklrn.com/quiz_player.php?qquiz_url=https%3A%2F%2Fawsdev.quiklrn.com%2Fuser%2Fcloud.php%3Fmethod%3Ddownload_public%26cloud_repository_id%3D470%26auth%3Dc85a3762c06ebd03cf247d18403eb3ea&auth_code={cookies.get("rememberme")}"
                }))
        return respond(200, json.dumps({
            "message": "User Logged In Failed!",
            "response_body": data,
            "status" : "401"
        }))
        
        # Handle response
        if data.get("status") == 401:
            return respond(401, json.dumps({ "message": "Login failed", "data": data }))
        elif "user_id" in data or data.get("status") == 200:
            return respond(200, json.dumps({
                "message": "Login successful",
                "data": data,
                "rememberme": cookies.get("rememberme")
            }))
        else:
            return respond(500, json.dumps({ "message": "Unexpected login response" }))

    except Exception as e:
        return respond(500, json.dumps({ "message": str(e) }))

        return respond(200, json.dumps({
                "redirect": "https://awsdev.quiklrn.com/user/login.php?email="
            }))
        # response = requests.get(api_url, params=params, allow_redirects=False)
        # header_text = response.headers
        # body = response.text
        return respond(200, json.dumps({
                "redirect": "https://awsdev.quiklrn.com/user/login.php?email="
            }))
    except Exception as e:
        return respond(500, json.dumps({ "message": "Server error", "error": str(e) }))

def respond(status, body, headers=None):
    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Methods": "*"
    }
    if headers:
        cors_headers.update(headers)
    return {
        "statusCode": status,
        "headers": cors_headers,
        "body": body
    }

def lambda_handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "")
    path = event.get("rawPath", "/")

    if method == "GET" and path == "/":
        with open("login.html", "r") as f:
            html = f.read()
        return respond(200, html, { "Content-Type": "text/html" })
        return respond(200, json.dumps({ "success": True, "message": "User registered successfully" }))

        with open("index.html", "r") as f:
            html = f.read()
        return respond(200, html, { "Content-Type": "text/html" })

    elif method == "GET" and path == "/hello":
        with open("login.html", "r") as f:
            html = f.read()
        return respond(200, html, { "Content-Type": "text/html" })
        return respond(200, json.dumps({ "success": True, "message": "User registered successfully" }))

    elif method == "POST" and path == "/login":
        try:
            body = json.loads(event.get("body", "{}"))
            useremail = body.get("useremail")
            password = body.get("password")
            
            # loginType = body.get("loginType")
            loginType = config.LOGIN_TYPE
            # return respond(200, json.dumps({ "success": loginType, "message": "User registered successfully" }))
            # return respond(200, json.dumps({ "success": loginType== 2, "message": "User registered successfully" }))
            if not useremail or not password:
                return respond(400, json.dumps({ "message": "Missing credentials" }))
            if loginType == 1:
                return dynamodb_login(useremail, password)
            if loginType == 2:
                return proxy_login(useremail, password, "App", "Email")
                
            # res = table.get_item(Key={ "useremail": useremail })
            # user = res.get("Item")

            # if user and user["password"] == password:
            # platform = body.get("platform", "App")
            # provider = body.get("provider", "Email")
            
            return proxy_login(useremail, password, "App", "Email")
            return respond(200, json.dumps({
            "redirect": "https://awsdev.quiklrn.com/user/login.php?email="
        }))

            return respond(401, json.dumps({ "message": "Invalid credentials" }))
        except Exception as e:
            return respond(500, json.dumps({ "message": str(e) }))

    elif method == "POST" and path == "/register":
        try:
            body = json.loads(event.get("body", "{}"))
            fullname = body.get("fullname")
            email = body.get("email")
            password = body.get("password")

            if not fullname or not email or not password:
                return respond(400, json.dumps({ "message": "Missing fields" }))

            # Check if user already exists
            res = table.get_item(Key={"useremail": email})
            if "Item" in res:
                return respond(409, json.dumps({ "message": "User already exists" }))

            # Hash password
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            table.put_item(Item={
                "useremail": email,
                "fullname": fullname,
                "password": hashed_pw
            })

            return respond(200, json.dumps({ "success": True, "message": "User registered successfully" }))

        except Exception as e:
            return respond(500, json.dumps({ "message": str(e) }))
    return respond(404, json.dumps({ "message": "Not found" }))
