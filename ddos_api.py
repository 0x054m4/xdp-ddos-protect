from fastapi import FastAPI, HTTPException
import subprocess
import ipaddress

app = FastAPI()


def validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP")


def run_cmd(action: str, ip: str):
    ip = validate_ip(ip)

    try:
        result = subprocess.run(
            ["ddos_ctl", action, ip],
            capture_output=True,
            text=True,
            timeout=5
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if result.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail=result.stderr.strip()
        )

    return {
        "ok": True,
        "action": action,
        "ip": ip,
        "output": result.stdout.strip()
    }


@app.post("/add/{ip}")
def add(ip: str):
    return run_cmd("add", ip)


@app.post("/del/{ip}")
def delete(ip: str):
    return run_cmd("del", ip)
