#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "liburing/compat.h"
#include "liburing/io_uring.h"
#include "liburing.h"
#include <assert.h>

#ifndef __NR_io_uring_enter
# define __NR_io_uring_enter		426
#endif

// #define DEBUG_IO_URING


static int __sys_io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
                                unsigned flags, sigset_t *sig) {
    
    int res = syscall(__NR_io_uring_enter, fd, to_submit, min_complete,
                   flags, sig, _NSIG / 8);
#ifdef DEBUG_IO_URING
    printf("[__sys_io_uring_enter]: syscall %d, fd: %d, submit: %d, min_complete: %d, flags: %d, sig: %p, sz: %d, res: %d\n",
		__NR_io_uring_enter, fd, to_submit, min_complete, flags, sig, _NSIG / 8, res);
#endif
    return res;
}

uint64_t occlum_ocall_io_uring_init(unsigned ring_size) {
#ifdef DEBUG_IO_URING
    printf("%s, ring_size: %d\n",
           __func__, ring_size);
#endif

    struct io_uring *ring = malloc(sizeof(struct io_uring));

    int ring_flags = IORING_SETUP_SQPOLL;
    // ring_flags = 0;
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



#define FD_NUM 16
#define RES_SIZE 10240

#define DEBUG_LOG

struct io_uring ring2;
int fds2[FD_NUM];
pthread_mutex_t sq_lock2;
pthread_mutex_t cq_lock2;
int req_id2;
int has_results2[RES_SIZE];
int results2[RES_SIZE];

void init_io_uring2() {
    int ring_flags = 0;
    ring_flags |= IORING_SETUP_SQPOLL;
    int ret = io_uring_queue_init(1024, &ring2, ring_flags);
    if (ret) {
        fprintf(stderr, "ring create failed: %d\n", ret);
    }

    for (int i = 0; i < FD_NUM; ++i) fds2[i] = -1;
    ret = io_uring_register_files(&ring2, fds2, FD_NUM);
    if (ret) {
        fprintf(stderr, "file reg failed: %d\n", ret);
    }

    assert(pthread_mutex_init(&sq_lock2, NULL) == 0);
    assert(pthread_mutex_init(&cq_lock2, NULL) == 0);
    req_id2 = 0;
    memset(has_results2, 0, sizeof(has_results2));
    memset(results2, 0, sizeof(results2));
    printf("init success\n");
}

int get_fixed_fd2(int fd) {
    for (int i = 0; i < FD_NUM; ++i) {
        if (fds2[i] == fd) {

            printf("fds: [");
            for (int i = 0; i < FD_NUM; ++i) printf("%d, ", fds2[i]);
            printf("]\n");
            
            return i;
        }
    }
    for (int i = 0; i < FD_NUM; ++i) {
        if (fds2[i] == -1) {
            int ret = io_uring_register_files_update(&ring2, i, &fd, 1);
            assert(ret == 1);
            fds2[i] = fd;

            printf("fds: [");
            for (int i = 0; i < FD_NUM; ++i) printf("%d, ", fds2[i]);
            printf("]\n");

            return i;
        }
    }
}

void c_clear_register_files2() {
    for (int i = 0; i < FD_NUM; ++i) {
        if (fds2[i] != -1) {
            int empty_fd = -1;
            int ret = io_uring_register_files_update(&ring2, i, &empty_fd, 1);
            assert(ret == 1);
            fds2[i] = empty_fd;
        }
    }
}

int submit2(int fd, int flags, struct msghdr* msg, int type, const char* str) {
    pthread_mutex_lock(&sq_lock2);
    #ifdef DEBUG_LOG
    printf("%s fd: %d\n", str, fd);
    #endif

    struct io_uring_sqe *sqe;

    int id = req_id2++ % RES_SIZE;

    sqe = io_uring_get_sqe(&ring2);
    assert(sqe != NULL);

    int fixed_fd = get_fixed_fd2(fd);
    #ifdef DEBUG_LOG
    printf("%s fd: %d, fixed_fd: %d\n", str, fd, fixed_fd);
    #endif

    if (type == IORING_OP_SENDMSG)
        io_uring_prep_sendmsg(sqe, fixed_fd, msg, flags);
    else if (type == IORING_OP_RECVMSG)
        io_uring_prep_recvmsg(sqe, fixed_fd, msg, flags);
    else fprintf(stderr, "type error!");
    
    sqe->flags |= IOSQE_FIXED_FILE;
    sqe->user_data = id;

    int ret = io_uring_submit(&ring2);

    #ifdef DEBUG_LOG
    printf("%s submit id (%d), ret %d, sq ready num: %d\n", str, id, ret, io_uring_sq_ready(&ring2));
    #endif

    pthread_mutex_unlock(&sq_lock2);

    return id;
}

int complete2(int target_id, const char* str) {
    struct io_uring_cqe *cqe;
    int res = 0;
    while (1) {
        pthread_mutex_lock(&cq_lock2);
        #ifdef DEBUG_LOG
        // printf("%s got cq lock, want id: %d, sq drop: %d, sq ready num: %d\n", str, target_id, *ring.sq.kdropped, io_uring_sq_ready(&ring));
        #endif

        if (has_results2[target_id] == 1) {
            res = results2[target_id];
            pthread_mutex_unlock(&cq_lock2);
            // printf("%s free cq lock\n", str);
            break;
        }
        else if (io_uring_peek_cqe(&ring2, &cqe) == 0) {
            int cqe_data = cqe->user_data;
            int cqe_res = cqe->res;
            int cq_ready = io_uring_cq_ready(&ring2);
            io_uring_cqe_seen(&ring2, cqe);
            
            if (cqe_data == target_id) {
                #ifdef DEBUG_LOG
                printf("%s get self cqe, user_data %d, res %d, cq_ready: %d\n", str, cqe_data, cqe_res, cq_ready);
                #endif
                res = cqe_res;
                pthread_mutex_unlock(&cq_lock2);
                // printf("%s free cq lock\n", str);
                break;
            }
            else {
                #ifdef DEBUG_LOG
                printf("%s get other cqe, user_data %d, res %d, want id: %d, cq_ready: %d\n", str, cqe_data, cqe_res, target_id, cq_ready);
                #endif
                has_results2[cqe_data] = 1;
                results2[cqe_data] = cqe_res;
            }
        }

        pthread_mutex_unlock(&cq_lock2);
    }
    return res;
}

int do_recvmsg2(int fd, struct msghdr * msg, int flags) {
    int id = submit2(fd, flags, msg, IORING_OP_RECVMSG, __func__);
    int res = complete2(id, __func__);
    return res;
}

int do_sendmsg2(int fd, struct msghdr * msg, int flags) {
    int id = submit2(fd, flags, msg, IORING_OP_SENDMSG, __func__);
    int res = complete2(id, __func__);
    return res;
}