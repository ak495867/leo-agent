from flask import request
import os

def run():
    command = request.args.get("cmd")
    os.system(command)
