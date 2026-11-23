from flask import request
import subprocess

def run():
    command = request.args.get("cmd")
    if command not in {"status", "version"}:
        raise ValueError("unsupported")
    subprocess.run(["/usr/bin/tool", command], shell=False, check=True)
