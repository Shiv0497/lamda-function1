import json
import os
import boto3
import bcrypt
import urllib.request
import urllib.parse
from http.cookies import SimpleCookie
import config
from config import (
    MOODLE_PROTOCOL,
    MOODLE_URL,
    MOODLE_LOGIN_URL,
    MOODLE_TOKEN,
    MOODLE_LOGIN_TOKEN,
    REDIRECTION,
    WEBSITE_URL
)

from http.cookies import SimpleCookie
from urllib import request, error, parse

# AWS Config
dynamodb = boto3.resource("dynamodb", region_name="ap-south-1")
table = dynamodb.Table("Login_table")

QUIKLRN_REDIRECT = "https://awsdev.quiklrn.com"  # global redirect placeholder

loginType = None  # 🌍 Global

# ✅ Helper function for responses
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


# ✅ Fetch HTML page for redirect
def proxy_fetch(url):
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req) as res:
            body = res.read().decode("utf-8")
            content_type = res.headers.get("Content-Type", "text/html")
        return respond(200, body, {"Content-Type": content_type})
    except Exception as e:
        print("Proxy Fetch Error:", str(e))
        return respond(500, json.dumps({"message": f"Proxy fetch failed: {str(e)}"}))


def proxy_login(email, password, platform, provider,loginType):
    try:
        # Always return redirect_to.html first (if required for REDIRECTION=3)
        if REDIRECTION == 3:
            with open("redirect_to.html", "r") as f:
                html = f.read()
            return respond(200, html, {"Content-Type": "text/html"})

        # Prepare request to Quiklrn login URL
        base_url = "https://awsdev.quiklrn.com/user/login.php"
        params = {
            "platform": platform,
            "email": email,
            "password": password,
            "provider": provider
        }
        full_url = f"{base_url}?{urllib.parse.urlencode(params)}"

        req = urllib.request.Request(full_url, method="POST")
        with urllib.request.urlopen(req) as res:
            headers = res.info()
            body = res.read().decode("utf-8")

        # Parse cookies
        cookies = {}
        set_cookie = headers.get_all("Set-Cookie")
        if set_cookie:
            for cookie_str in set_cookie:
                cookie = SimpleCookie()
                cookie.load(cookie_str)
                for key, morsel in cookie.items():
                    cookies[key] = morsel.value

        # Parse JSON response
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return respond(500, json.dumps({"message": "Invalid JSON from login server"}))

        # Handle REDIRECTION == 2 (Moodle)
        if loginType == "2" and "user_id" in data:
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

        # Handle REDIRECTION == 1 (Set global redirect and return /quiklrn)
        if loginType == "1" and "user_id" in data:
            #global QUIKLRN_REDIRECT
            #QUIKLRN_REDIRECT = f"https://awsdev.quiklrn.com/?rememberme={cookies.get('rememberme')}"
            #return respond(200, json.dumps({
            #    "redirect_path": "/quiklrn",
            #    "status": 200
            #}))

            # ✅ Handle success/failure cases
            if "user_id" in data or data.get("status") == 200:
                return respond(200, json.dumps({
                    "message": "User Logged In Successfully!",
                    "response_body": data,
                    "email": email,
                    "status": 200,
                    "rememberme": cookies.get("rememberme"),
                    "redirect": f"https://awsdev.quiklrn.com/?rememberme={cookies.get('rememberme')}"
                }))
            else:
                return respond(401, json.dumps({
                    "message": "Login failed",
                    "response_body": data,
                    "status": 401
                }))

    except Exception as e:
        return respond(500, json.dumps({"message": f"Server error: {str(e)}"}))

# ✅ DynamoDB Login
def dynamodb_login(email, password):
    try:
        print(f"Login attempt for: {email}")
        res = table.get_item(Key={"useremail": email})
        user = res.get("Item")

        if not user:
            return respond(401, json.dumps({"message": "User not found"}))

        if bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):

            # Example usage:
            desired_length = 32
            strict_salt_python = generate_strict_length_salt(desired_length)

            users = [
                {"useremail": email, "rememberme": strict_salt_python},
            ]
            for user in users:
                # table.update_item(
                #     Key={"useremail": user["useremail"]},
                #     UpdateExpression="SET user_id = :uid, rememberme = :rm",
                #     ExpressionAttributeValues={
                #         ":uid": user["user_id"],
                #         ":rm": user["rememberme"]
                #     }
                # )

                table.update_item(
                    Key={"useremail": user["useremail"]},
                    UpdateExpression="SET  rememberme = :rm",
                    ExpressionAttributeValues={
                        ":rm": user["rememberme"]
                    }
                )

            # return respond(400, json.dumps({"message": "Columns added successfully!"}))
            # print("✅ Columns added successfully!")
            return respond(200, json.dumps({
                    "message": "User Logged In Successfully!",
                    "response_body": users,
                    "email": email,
                    "status": 200,
                    "rememberme": strict_salt_python,
                    
                    "redirect": f"https://enrollment-dev.quiklrn.com/quiz_player.php?"
                                "qquiz_url=https%3A%2F%2Fawsdev.quiklrn.com%2Fuser%2Fcloud.php%3Fmethod%3Ddownload_public"
                                "%26cloud_repository_id%3D470%26auth%3Dc85a3762c06ebd03cf247d18403eb3ea"
                                f"&auth_code={strict_salt_python}"
                }))
  
            # return respond(200, json.dumps({
            #     "message": "Login successful",
            #     "user": user,
            #     "status": 200
            # }))
        else:
            return respond(401, json.dumps({"message": "Invalid password"}))

    except Exception as e:
        print("Login Error:", str(e))
        return respond(500, json.dumps({"message": str(e)}))


# ✅ DynamoDB Register
def dynamodb_register(fullname, email, password):
    try:
        res = table.get_item(Key={"useremail": email})
        if "Item" in res:
            return respond(409, json.dumps({"message": "User already exists"}))

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        table.put_item(Item={
            "useremail": email,
            "fullname": fullname,
            "password": hashed_pw
        })

        return respond(200, json.dumps({"success": True, "message": "User registered successfully"}))

    except Exception as e:
        print("Register Error:", str(e))
        return respond(500, json.dumps({"message": str(e)}))



import secrets
import string

def generate_strict_length_salt(length):
    """
    Generates a cryptographically secure random salt of an exact specified length,
    using only alphanumeric characters (A-Z, a-z, 0-9).

    Args:
        length (int): The desired exact length of the salt.

    Returns:
        str: The generated salt.
    """
    # Define the pool of characters: alphanumeric (letters and digits)
    alphabet = string.ascii_letters + string.digits

    # Generate the salt by securely choosing characters from the alphabet
    # for the specified length.
    salt = ''.join(secrets.choice(alphabet) for _ in range(length))

    return salt

# ✅ Lambda Handler
def lambda_handler(event, context):

    
    method = event.get("requestContext", {}).get("http", {}).get("method", "")
    path = event.get("rawPath", "/")

    try:
        if method == "GET" and path == "/":
            with open("login.html", "r") as f:
                html = f.read()
            return respond(200, html, {"Content-Type": "text/html"})

        elif method == "GET" and path == "/quiklrn":
            if not QUIKLRN_REDIRECT:
                return respond(400, json.dumps({"message": "Missing redirect target"}))
            return proxy_fetch(QUIKLRN_REDIRECT)

        elif method == "POST" and path == "/login":

            try:
                # Get JSON body
                body = json.loads(event.get("body", "{}") or "{}")
                email = body.get("useremail")
                password = body.get("password")
                loginType = body.get("loginType")

                if not email or not password:
                    return respond(400, json.dumps({"message": "Missing credentials"}))

                if loginType == "0":
                    return dynamodb_login(email, password)
                if loginType == "1" or loginType == "2":
                    return proxy_login(email, password, "App", "Email",loginType)
                # return respond(200, json.dumps({
                #     "email": email,
                #     "password": password,
                #     "loginType": loginType
                # }))

            except Exception as e:
                return respond(500, json.dumps({"error": str(e)}))

            
            # body = json.loads(event.get("body", "{}"))
            # email = body.get("useremail")
            # password = body.get("password")
           
            # URLparams = event.get("queryStringParameters", {}) or {}
            # loginType = URLparams.get("loginType")
            # return respond(400, json.dumps({"message": loginType}))

            # if not email or not password:
            #     return respond(400, json.dumps({"message": "Missing credentials"}))
            # loginType = config.LOGIN_TYPE
            
          
        elif method == "POST" and path == "/register":
            body = json.loads(event.get("body", "{}"))
            fullname = body.get("fullname")
            email = body.get("email")
            password = body.get("password")

            if not fullname or not email or not password:
                return respond(400, json.dumps({"message": "Missing fields"}))

            return dynamodb_register(fullname, email, password)

        else:
            return respond(404, json.dumps({"message": "Not Found"}))

    except Exception as e:
        import traceback
        print("ERROR:", str(e))
        print(traceback.format_exc())
        return respond(500, json.dumps({"message": str(e)}))
