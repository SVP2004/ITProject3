import socket
import signal
import sys
import random

# Read a command line argument for the port where the server
# must run.
port = 8080
if len(sys.argv) > 1:
    port = int(sys.argv[1])
    print("Using port " +str(port))
else:
    print("Using default port 8080")
hostname = socket.gethostname()
server_ip = socket.gethostbyname(hostname)

# Start a listening server socket on the port
sock = socket.socket()
sock.bind(('', port))
sock.listen(2)

### Contents of pages we will serve.
# Login form
login_form = """
   <form action = "http://%s" method = "post">
   Name: <input type = "text" name = "username">  <br/>
   Password: <input type = "text" name = "password" /> <br/>
   <input type = "submit" value = "Submit" />
   </form>
"""
# Default: Login page.
login_page = "<h1>Please login</h1>" + login_form
# Error page for bad credentials
bad_creds_page = "<h1>Bad user/pass! Try again</h1>" + login_form
# Successful logout
logout_page = "<h1>Logged out successfully</h1>" + login_form
# A part of the page that will be displayed after successful
# login or the presentation of a valid cookie
success_page = """
   <h1>Welcome!</h1>
   <form action="http://%s" method = "post">
   <input type = "hidden" name = "action" value = "logout" />
   <input type = "submit" value = "Click here to logout" />
   </form>
   <br/><br/>
   <h1>Your secret data is here:</h1>
"""

#### Helper functions
# Printing.
def print_value(tag, value):
    print("Here is the", tag)
    print("\"\"\"")
    print(value)
    print("\"\"\"")
    print()

# Signal handler for graceful exit
def sigint_handler(sig, frame):
    print('Finishing up by closing listening socket...')
    sock.close()
    sys.exit(0)
# Register the signal handler
signal.signal(signal.SIGINT, sigint_handler)


# TODO: put your application logic here!
# Read login credentials for all the users
# Read secret data of all the users

###USER CREDENTIALS
#opening passwords.txt
with open('passwords.txt', 'r') as f:
    lines = f.readlines()

#creating empty dict
credentials = {}

#looping through lines in text file
for line in lines:
    #split the line on user/pass
    username, password = line.strip().split()
    #add to credentials
    credentials[username] = password




###SECRETS
#opening passwords.txt
with open('secrets.txt', 'r') as f:
    lines = f.readlines()

#creating empty dict
secrets = {}

#looping through lines in text file
for line in lines:
    #split the line on user/pass
    username, secret = line.strip().split()
    #add to credentials
    secrets[username] = secret


#Store Session Cookies
session_cookies = {}


### Loop to accept incoming HTTP connections and respond.
while True:
    client, addr = sock.accept()
    req = client.recv(1024)

    # Let's pick the headers and entity body apart
    header_body = req.decode().split('\r\n\r\n')
    headers = header_body[0]
    body = '' if len(header_body) == 1 else header_body[1]
    print_value('headers', headers)
    print_value('entity body', body)


    #Dynamic Host/Port configuration
    submit_hostport = "%s:%d" % (server_ip, port)

    for line in headers.split('\r\n'):
        if line.startswith("Host:"):
            host_header = line.split(": ")[1]
            host_parts = host_header.split(':')

            dynamic_hostname = host_parts[0]
            dynamic_port = port if len(host_parts) == 1 else int(host_parts[1])

            submit_hostport = "%s:%d" % (dynamic_hostname, dynamic_port)
            break


    # TODO: Put your application logic here!
    # Parse headers and body and perform various actions
    request_line = headers.split('\r\n')[0]
    if request_line:
        method = request_line.split()[0]
    else:
        method = None
    headers_to_send = ''
    html_content_to_send = login_page % submit_hostport ##Default Page

    #Cookie Validation
    cookie = None
    for line in headers.split('\r\n'):
        if line.startswith("Cookie:"):
            cookie = line.split("Cookie: token=")[-1]
            break
    
    logout = False
    # Case E: Logout, clear cookie
    if method == 'POST' and 'action=logout' in body:
        if cookie in session_cookies:
            del session_cookies[cookie]
            headers_to_send = 'Set-Cookie: token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax\r\n'
            html_content_to_send = logout_page % submit_hostport
            cookie = None  # Explicitly clear cookie reference
            logout = True
        
# Case C: Valid cookie, serve secret page
    elif cookie and cookie in session_cookies and method == "GET":
        username = session_cookies[cookie]
        html_content_to_send = (success_page % submit_hostport) + secrets[username]
    
    # Case D: Invalid or Missing Cookie, Default to Login Page
    elif (not cookie or cookie not in session_cookies) and method == "GET":
        html_content_to_send = login_page % submit_hostport
        
        # Case A: Login attempt with user/pass
    if method == 'POST' and not logout and 'username' in body and 'password' in body:
        params = dict(pair.split('=') for pair in body.split('&'))
        username = params.get('username')
        password = params.get('password')
        if username and password and username in credentials and credentials[username] == password:
            # Successful Login, set new cookie
            new_cookie = str(random.getrandbits(64))
            session_cookies[new_cookie] = username
            headers_to_send = f'Set-Cookie: token={new_cookie}\r\n'
            html_content_to_send = (success_page % submit_hostport) + secrets[username]
        else:
            # Case B: Failed Login
            html_content_to_send = (bad_creds_page % submit_hostport)


















    # if cookie and cookie in session_cookies and method != "POST":
    #     #Case C: Valid cookie, serve secret page
    #     username = session_cookies[cookie]
    #     html_content_to_send = (success_page % submit_hostport) + secrets[username]
    # else:
    #     if method == 'POST':
    #         params = dict(pair.split('=') for pair in body.split('&'))
    #         action = params.get('action')
    #         username = params.get('username')
    #         password = params.get('password')

    #         #Case E: Logout, clear cookie
    #         if action == 'logout' and cookie in session_cookies:
    #             del session_cookies[cookie]
    #             headers_to_send = 'Set-Cookie: token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax\r\n'
    #             html_content_to_send = logout_page % submit_hostport
    #             cookie = None  # Explicitly clear cookie reference
            
    #         #Case A: Login attempt with user/pass
    #         elif username and password:
    #             if username in credentials and credentials[username] == password:
    #                 #Succesful Login, set new cookie
    #                 new_cookie = str(random.getrandbits(64))
    #                 session_cookies[new_cookie] = username
    #                 headers_to_send = f'Set-Cookie: token={new_cookie}\r\n'
    #                 html_content_to_send = (success_page % submit_hostport) + secrets[username]
    #             else:
    #                 #Case B: Failed Login
    #                 html_content_to_send = (bad_creds_page % submit_hostport)

    #         else:
    #             #Case B: Missing or Incorrect Credentials
    #             html_content_to_send = (bad_creds_page % submit_hostport)

    #     else:
    #         #CaseD: Invalid or Missing Cookie, Default to Login Page
    #         html_content_to_send = login_page % submit_hostport
        


    # OPTIONAL TODO:
    # Set up the port/hostname for the form's submit URL.
    # If you want POSTing to your server to
    # work even when the server and client are on different
    # machines, the form submit URL must reflect the `Host:`
    # header on the request.
    # Change the submit_hostport variable to reflect this.
    # This part is optional, and might even be fun.
    # By default, as set up below, POSTing the form will
    # always send the request to the domain name returned by
    # socket.gethostname().
    
    

    # You need to set the variables:
    # (1) `html_content_to_send` => add the HTML content you'd
    # like to send to the client.
    # Right now, we just send the default login page.
    # But other possibilities exist, including
    # html_content_to_send = (success_page % submit_hostport) + <secret>
    # html_content_to_send = bad_creds_page % submit_hostport
    # html_content_to_send = logout_page % submit_hostport
    
    # (2) `headers_to_send` => add any additional headers
    # you'd like to send the client?
    # Right now, we don't send any extra headers.

    # Construct and send the final response
    response  = 'HTTP/1.1 200 OK\r\n'
    response += headers_to_send
    response += 'Content-Type: text/html\r\n\r\n'
    response += html_content_to_send
    print_value('response', response)    
    client.send(response.encode())
    client.close()
    
    print("Served one request/connection!")
    print()

# We will never actually get here.
# Close the listening socket
sock.close()
