#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "liburing/compat.h"
#include "liburing/io_uring.h"
#include "liburing.h"

#ifndef __NR_io_uring_enter
# define __NR_io_uring_enter		426
#endif

// #define DEBUG_IO_URING


static int __sys_io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
                                unsigned flags, sigset_t *sig) {
    return syscall(__NR_io_uring_enter, fd, to_submit, min_complete,
                   flags, sig, _NSIG / 8);
}

uint64_t occlum_ocall_io_uring_init(unsigned ring_size) {
#ifdef DEBUG_IO_URING
    printf("%s, ring_size: %d\n",
           __func__, ring_size);
#endif

    struct io_uring *ring = malloc(sizeof(struct io_uring));

    int ring_flags = IORING_SETUP_SQPOLL;
    int ret = io_uring_queue_init(ring_size, ring, ring_flags);
    if (ret < 0) {
        fprintf(stderr, "[%s] io_uring_queue_init error: %s\n", __func__, strerror(-ret));
        return 0;
    }

    return (uint64_t)ring;
}

void occlum_ocall_io_uring_exit(uint64_t io_uring_addr) {
#ifdef DEBUG_IO_URING
    printf("%s, io_uring_addr: %p\n",
           __func__, (void *)io_uring_addr);
#endif

    io_uring_unregister_files((struct io_uring *)io_uring_addr);
    io_uring_queue_exit((struct io_uring *)io_uring_addr);
}

int occlum_ocall_io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
                                unsigned flags) {
#ifdef DEBUG_IO_URING
    printf("%s, fd: %d, to_submit: %d, min_complete: %d, flags: %d\n",
           __func__, fd, to_submit, min_complete, flags);
#endif

    return __sys_io_uring_enter(fd, to_submit, min_complete, flags, NULL);
}

int occlum_ocall_io_uring_register_files(uint64_t io_uring_addr, int *fds,
        unsigned fds_size) {
#ifdef DEBUG_IO_URING
    printf("%s, io_uring_addr: %p, fds_size: %d\n",
           __func__, (void *)io_uring_addr, fds_size);
    for (int i = 0; i < fds_size; ++i) { printf("%d, ", fds[i]); }
    printf("\n");
#endif

    return io_uring_register_files((struct io_uring *)io_uring_addr, fds, fds_size);
}

int occlum_ocall_io_uring_update_file(uint64_t io_uring_addr, int fd, unsigned offset) {
#ifdef DEBUG_IO_URING
    printf("%s, io_uring_addr: %p, fd: %d, offset: %d\n",
           __func__, (void *)io_uring_addr, fd, offset);
#endif

    return io_uring_register_files_update((struct io_uring *)io_uring_addr, offset, &fd, 1);
}

void occlum_ocall_io_uring_debug(uint64_t addr) {
    struct msghdr *msg = (struct msghdr *)addr;
    fprintf(stderr, "name: %p, %d, iov: %p, %d, control: %p, %d, flag: %d\n",
               msg->msg_name, msg->msg_namelen, 
               msg->msg_iov, msg->msg_iovlen, 
               msg->msg_control, msg->msg_controllen, msg->msg_flags);

    if (msg->msg_iovlen >= 1) {
        memset(msg->msg_iov[0].iov_base, 0, msg->msg_iov[0].iov_len);
        fprintf(stderr, "iov %p, %d\n",
               msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len);
        for (int i = 0; i < msg->msg_iov[0].iov_len; ++i) {
            char ch = *((char*)msg->msg_iov[0].iov_base + i);
            fprintf(stderr, "[%d]", ch);
        }
        fprintf(stderr, "\n");
    }
}