#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A kernel module that hooks sys_open and checks for malicious filenames");
MODULE_VERSION("0.2");

unsigned long **sys_call_table;
asmlinkage int (*original_sys_open)(const char __user *, int, umode_t);

asmlinkage int hooked_sys_open(const char __user *filename, int flags, umode_t mode) {
    char *kern_filename = kmalloc(256, GFP_KERNEL);
    if (kern_filename) {
        copy_from_user(kern_filename, filename, 255);
        kern_filename[255] = '\0';

        printk(KERN_INFO "Attempting to open file: %s\n", kern_filename);

        if (strstr(kern_filename, "malicious") != NULL) {
            printk(KERN_ALERT "Blocked attempt to open a malicious file: %s\n", kern_filename);
            kfree(kern_filename);
            return -EACCES;  // Return access denied
        }

        kfree(kern_filename);
    }
    return original_sys_open(filename, flags, mode);
}

static unsigned long **find_sys_call_table(void) {
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;

    while (offset < ULLONG_MAX) {
        sct = (unsigned long **)offset;

        if (sct[__NR_close] == (unsigned long *)sys_close) 
            return sct;

        offset += sizeof(void *);
    }
    return NULL;
}

static int __init syscall_init(void) {
    sys_call_table = find_sys_call_table();

    if (!sys_call_table)
        return -1;

    write_cr0(read_cr0() & (~0x10000));
    original_sys_open = (void *)sys_call_table[__NR_open];
    sys_call_table[__NR_open] = (unsigned long *)hooked_sys_open;
    write_cr0(read_cr0() | 0x10000);

    printk(KERN_INFO "Module loaded: sys_open hooked\n");
    return 0;
}

static void __exit syscall_release(void) {
    if (sys_call_table) {
        write_cr0(read_cr0() & (~0x10000));
        sys_call_table[__NR_open] = (unsigned long *)original_sys_open;
        write_cr0(read_cr0() | 0x10000);
    }
    printk(KERN_INFO "Module unloaded: sys_open restored\n");
}

module_init(syscall_init);
module_exit(syscall_release);
