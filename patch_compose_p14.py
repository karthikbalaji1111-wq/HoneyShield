import yaml
import sys

with open("docker-compose.yml", "r") as f:
    compose = yaml.safe_load(f)

for svc_name, svc in compose.get("services", {}).items():
    if svc_name == "redis":
        continue
    
    svc["read_only"] = True
    svc["security_opt"] = ["no-new-privileges:true"]

    if svc_name == "backend":
        svc["cap_drop"] = ["ALL"]
        svc["tmpfs"] = ["/tmp"]
        svc["deploy"] = {"replicas": 1}
        # Update healthcheck endpoint
        if "healthcheck" in svc and "test" in svc["healthcheck"]:
            test_cmd = svc["healthcheck"]["test"]
            for i, arg in enumerate(test_cmd):
                if "http://127.0.0.1:8000/api/v1/ready" not in arg and "127.0.0.1:8000" in arg:
                    test_cmd[i] = arg.replace("http://127.0.0.1:8000/health", "http://127.0.0.1:8000/api/v1/ready")

    elif svc_name == "nginx":
        svc["cap_drop"] = ["ALL"]
        svc["cap_add"] = ["NET_BIND_SERVICE", "SETUID", "SETGID", "CHOWN", "DAC_OVERRIDE"]
        svc["tmpfs"] = [
            "/var/cache/nginx",
            "/var/run",
            "/var/log/nginx",
            "/tmp"
        ]
        
    elif svc_name == "postgres":
        svc["cap_drop"] = ["ALL"]
        svc["cap_add"] = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"]
        svc["tmpfs"] = ["/var/run/postgresql", "/tmp"]

    svc["logging"] = {
        "driver": "json-file",
        "options": {
            "max-size": "10m",
            "max-file": "3"
        }
    }

with open("docker-compose.yml", "w") as f:
    yaml.dump(compose, f, sort_keys=False)
