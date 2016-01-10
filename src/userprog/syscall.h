#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "threads/thread.h"

void syscall_init (void);

// FOR PROJECT2
void push_exit_record(int status);

extern struct list exit_list;
extern int load_flag;

struct exit_record {
    tid_t tid;
    int status;

    struct list_elem elem;
};

#endif /* userprog/syscall.h */
