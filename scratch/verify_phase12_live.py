import urllib.request
import urllib.error
import ssl

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        return fp
    http_error_301 = http_error_303 = http_error_307 = http_error_302

opener = urllib.request.build_opener(NoRedirectHandler, urllib.request.HTTPSHandler(context=context))
urllib.request.install_opener(opener)

print("Testing HTTP to HTTPS redirect...")
req = urllib.request.Request("http://127.0.0.1:8080/api/v1/health", headers={"Host": "localhost"})
try:
    response = urllib.request.urlopen(req, context=context)
    print(f"SUCCESS: Got {response.status} redirect!")
    print(f"Location: {response.headers.get('Location')}")
except Exception as e:
    print(f"FAILED: Expected redirect, got {e}")

print("\nTesting HTTPS direct connection and HSTS...")
req = urllib.request.Request("https://127.0.0.1:8443/api/v1/health", headers={"Host": "localhost"})
try:
    response = urllib.request.urlopen(req, context=context)
    print(f"SUCCESS: Got {response.status} from HTTPS")
    if "Strict-Transport-Security" in response.headers:
        print("SUCCESS: HSTS header is present!")
        print(f"Header value: {response.headers['Strict-Transport-Security']}")
    else:
        print("FAILED: Missing HSTS header!")
        print(response.headers)
except Exception as e:
    print(f"FAILED: Error connecting to HTTPS: {e}")
