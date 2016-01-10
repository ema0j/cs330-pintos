#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <string.h>

static void syscall_handler (struct intr_frame *);

int load_flag;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// FOR PROJECT2
void
push_exit_record(int status)
{
    struct thread *parent = thread_current()->parent;

    struct list_elem *e;
    for( e = list_begin(&parent->child_list); e != list_end(&parent->child_list); e = list_next(e) )
    {
        struct tid_data *child = list_entry(e, struct tid_data, elem);
        if ( child->tid == thread_current()->tid ){
            child->exit_status = status;
        }
    }

    printf("%s: exit(%d)\n", thread_current()->name, status);
    sema_up(&sema_wait);
}

// FOR PROJECT2
static bool
is_validated_ptr(void* esp, int num)
{
    int i;
    for ( i = 0; i <= num; i++ )
    {
        if ( is_kernel_vaddr((esp + (4 * i))) || 
                (esp + (4 * i)) == NULL ||
                pagedir_get_page(thread_current()->pagedir, esp + (4 * i)) == NULL )
        {
            push_exit_record(-1);
            thread_exit();
            return false;
        }
    }

    return true;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
    /* FOR PROJECT2 */
    // TODO : implement syscall_handler
   
    if ( !is_validated_ptr(f->esp, 0) )
        return;
        
    int syscall_number = *((int *)f->esp);
    struct thread *curr = thread_current();

    if ( syscall_number == SYS_HALT )
    {
        power_off();
    }
    else if ( syscall_number == SYS_EXIT )
    {
        if ( !is_validated_ptr(f->esp, 1) )
            return;
        
        int exit_status = *((int *)(f->esp + 4));

        push_exit_record(exit_status);
        
        thread_exit();
    }
    else if ( syscall_number == SYS_EXEC )
    {
        //printf("parent %d exec child\n", thread_current()->tid);
        load_flag = 0;
        if ( !is_validated_ptr(f->esp, 1) )
            return;
        
        char *file = *((char **)(f->esp + 4));
        
        if ( file == NULL )
        {
            push_exit_record(-1);
            thread_exit();
        }
        else 
        {
            char *fn_copy, *save_ptr;
            fn_copy = palloc_get_page(PAL_USER);
            strlcpy(fn_copy, file, PGSIZE);

            struct file *test_existed = filesys_open(strtok_r(fn_copy, " ", &save_ptr));

            if ( test_existed == NULL )
            {
                f->eax = -1;
                file_close(test_existed);
                palloc_free_page(fn_copy);
                return;
            }

            tid_t tid = process_execute(file);
            //printf("child exec %d %d\n", tid, load_flag);
            
           while ( load_flag == 0 )
                barrier();

            //printf("after while child exec %d %d\n", tid, load_flag);
            f->eax = tid;
            palloc_free_page(fn_copy);
        }
    }
    else if ( syscall_number == SYS_WAIT )
    {
        if ( !is_validated_ptr(f->esp, 2) )
            return;
        
        int pid = *((int *)(f->esp +4));
        int wait_code = process_wait(pid);
        //printf("wait %d %d\n", pid, wait_code);
        f->eax = wait_code;

    }
    else if ( syscall_number == SYS_CREATE )
    {
        if ( !is_validated_ptr(f->esp, 2) )
            return;

        char *file = *((char **)(f->esp + 4));
        unsigned int initial_size = *((unsigned int *)(f->esp + 8));

        if ( file == NULL )
        {
            push_exit_record(-1);
            thread_exit();
        }
        else 
        {
            if ( strlen(file) == 0 ||strlen(file) > 14 )
                f->eax = 0;
            else
                f->eax = filesys_create(file, initial_size);
        }
    }
    else if ( syscall_number == SYS_REMOVE )
    {
        if ( !is_validated_ptr(f->esp, 1) )
            return;

        char *file = *((char **)(f->esp + 4));

        f->eax = filesys_remove(file);
    }
    else if ( syscall_number == SYS_OPEN )
    {
        if ( !is_validated_ptr(f->esp, 1) ){
            return;
        }

        char *file = *((char **)(f->esp + 4));

        if ( file == NULL )
            f->eax = -1;
        else
        {
            struct file *file_opened = palloc_get_page(PAL_USER);
            file_opened = filesys_open(file);

            if ( file_opened == NULL )
                f->eax = -1;
            else
            {
                struct file_descriptor *descriptor = palloc_get_page(PAL_USER);
                descriptor->fd = curr->fd_cnt;
                descriptor->f = file_opened;

                if ( strcmp(thread_current()->name, file) == 0 )
                    file_deny_write(descriptor->f);

                list_push_back(&curr->fd_list, &descriptor->elem);
                f->eax = descriptor->fd;
                curr->fd_cnt += 1;
            }
        }
    }
    else if ( syscall_number == SYS_FILESIZE )
    {
        if ( !is_validated_ptr(f->esp, 1) )
            return;

        int fd = *((int *)(f->esp + 4));

        struct list_elem *e;
        for ( e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e) )
        {
            struct file_descriptor *descriptor = list_entry(e, struct file_descriptor,elem);

            if ( descriptor->fd == fd )
            {
                f->eax = file_length(descriptor->f);
                break;
            }
        }
    }
    else if ( syscall_number == SYS_READ )
    {
        if ( !is_validated_ptr(f->esp, 3) )
            return;

        int fd = *((int *)(f->esp + 4));
        void *buffer = *((void **)(f->esp + 8));
        unsigned int size = *((unsigned int *)(f->esp + 12));

        if ( fd == 0 )
            f->eax = input_getc();
        else
        {
            struct list_elem *e;
            for ( e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e) )
            {
                struct file_descriptor *descriptor = list_entry(e, struct file_descriptor,elem);

                if ( descriptor->fd == fd )
                {
                    f->eax = (uint32_t)file_read(descriptor->f, buffer, size);
                    break;
                }
            }
        }
    }
    else if ( syscall_number == SYS_WRITE )
    {
        if ( !is_validated_ptr(f->esp, 3) )
            return;

        int fd = *((int *)(f->esp + 4));
        void *buffer = *((void **)(f->esp + 8));
        unsigned int size = *((unsigned int *)(f->esp + 12));

        if ( buffer == NULL )
        {
            push_exit_record(-1);
            thread_exit();
            return;
        }

        if ( fd == 1 )
            putbuf(buffer, size);
        else
        {
            struct list_elem *e;
            for ( e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e) )
            {
                struct file_descriptor *descriptor = list_entry(e, struct file_descriptor,elem);

                if ( descriptor->fd == fd )
                {
                    f->eax = (uint32_t)file_write(descriptor->f, buffer, size);
                    break;
                }
            }
        }
    }
    else if ( syscall_number == SYS_SEEK )
    {
        if ( !is_validated_ptr(f->esp, 2) )
            return;

        int fd = *((int *)(f->esp + 4));
        unsigned int position = *((unsigned int *)(f->esp + 8));

        struct list_elem *e;
        for ( e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e) )
        {
            struct file_descriptor *descriptor = list_entry(e, struct file_descriptor,elem);

            if ( descriptor->fd == fd )
            {
                file_seek(descriptor->f, position);
                break;
            }
        }
    }
    else if ( syscall_number == SYS_TELL )
    {
        if ( !is_validated_ptr(f->esp, 1) )
            return;

        int fd = *((int *)(f->esp + 4));

        struct list_elem *e;
        for ( e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e) )
        {
            struct file_descriptor *descriptor = list_entry(e, struct file_descriptor,elem);

            if ( descriptor->fd == fd )
            {
                f->eax = file_tell(descriptor->f);
                break;
            }
        }
    }
    else if ( syscall_number == SYS_CLOSE )
    {
        if ( !is_validated_ptr(f->esp, 1) )
            return;

        int fd = *((int *)(f->esp + 4));

        struct list_elem *e;
        for ( e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e) )
        {
            struct file_descriptor *descriptor = list_entry(e, struct file_descriptor,elem);

            if ( descriptor->fd == fd )
            {
                file_close(descriptor->f);
                list_remove(e);
                palloc_free_page(descriptor);

                break;
            }
        }
    }
    /************************************************************************/
}
