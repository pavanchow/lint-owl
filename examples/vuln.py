import os

def handle(request):
    host = request.args.get("host")
    cmd = "ping -c 1 " + host
    os.system(cmd)
