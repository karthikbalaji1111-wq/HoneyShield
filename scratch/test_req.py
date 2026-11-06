import urllib.request

req = urllib.request.Request("http://127.0.0.1:8001/")
req.add_header("X-Forwarded-For", "9.9.9.9")
try:
    with urllib.request.urlopen(req) as response:
        print(response.read().decode())
except Exception as e:
    print(e)
