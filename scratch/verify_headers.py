import urllib.request
import ssl
import json

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

req = urllib.request.Request("https://127.0.0.1:8443/", headers={"Host": "localhost"})
try:
    response = urllib.request.urlopen(req, context=context)
    print("Response headers:")
    print(response.headers)
    print("Response body:")
    print(response.read().decode())
except Exception as e:
    print(e)
