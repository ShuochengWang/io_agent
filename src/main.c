#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <assert.h>
#include <pthread.h>

#include "liburing.h"

#define ECHO_MSG "msg for client/server test"
#define RESPONSE "ACK"
#define DEFAULT_MSG "Hello World!\n"

#define FD_NUM 128
#define RES_SIZE 10240

// #define DEBUG_LOG
// #define USE_C_IO_URING

#define THROW_ERROR(fmt, ...)   do { \
    printf("\t\tERROR:" fmt " in func %s at line %d of file %s\n", \
    ##__VA_ARGS__, __func__, __LINE__, __FILE__); \
    return -1; \
} while (0)

struct io_uring ring;
int fds[FD_NUM];
pthread_mutex_t sq_lock;
pthread_mutex_t cq_lock;
pthread_t thread_id;
int req_id;
int has_results[RES_SIZE];
int results[RES_SIZE];

int test_fd_server;
int test_fd_client;

void init_io_uring() {
    int ring_flags = 0;
    ring_flags |= IORING_SETUP_SQPOLL;
    int ret = io_uring_queue_init(1024, &ring, ring_flags);
    if (ret) {
        fprintf(stderr, "ring create failed: %d\n", ret);
    }

    for (int i = 0; i < FD_NUM; ++i) fds[i] = -1;
    ret = io_uring_register_files(&ring, fds, FD_NUM);
    if (ret) {
        fprintf(stderr, "file reg failed: %d\n", ret);
    }

    assert(pthread_mutex_init(&sq_lock, NULL) == 0);
    assert(pthread_mutex_init(&cq_lock, NULL) == 0);
    req_id = 0;
    memset(has_results, 0, sizeof(has_results));
    memset(results, 0, sizeof(results));
}

void destroy_io_uring() {
    io_uring_queue_exit(&ring);
    pthread_mutex_destroy(&sq_lock);
    pthread_mutex_destroy(&cq_lock);
}

int get_fixed_fd(int fd) {
    for (int i = 0; i < FD_NUM; ++i) {
        if (fds[i] == fd) return i;
    }
    for (int i = 0; i < FD_NUM; ++i) {
        if (fds[i] == -1) {
            int ret = io_uring_register_files_update(&ring, i, &fd, 1);
            assert(ret == 1);
            fds[i] = fd;
            return i;
        }
    }
}

int submit(int fd, int flags, struct msghdr* msg, int type, const char* str) {
    pthread_mutex_lock(&sq_lock);
    #ifdef DEBUG_LOG
    printf("%s fd: %d\n", str, fd);
    #endif

    struct io_uring_sqe *sqe;

    int id = req_id++ % RES_SIZE;

    sqe = io_uring_get_sqe(&ring);
    assert(sqe != NULL);

    int fixed_fd = get_fixed_fd(fd);
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

    int ret = io_uring_submit(&ring);

    #ifdef DEBUG_LOG
    printf("%s submit id (%d), ret %d, sq ready num: %d\n", str, id, ret, io_uring_sq_ready(&ring));
    #endif

    pthread_mutex_unlock(&sq_lock);

    return id;
}

int complete(int target_id, const char* str) {
    struct io_uring_cqe *cqe;
    int res = 0;
    while (1) {
        pthread_mutex_lock(&cq_lock);
        #ifdef DEBUG_LOG
        // printf("%s got cq lock, want id: %d, sq drop: %d, sq ready num: %d\n", str, target_id, *ring.sq.kdropped, io_uring_sq_ready(&ring));
        #endif

        if (has_results[target_id] == 1) {
            res = results[target_id];
            pthread_mutex_unlock(&cq_lock);
            // printf("%s free cq lock\n", str);
            break;
        }
        else if (io_uring_peek_cqe(&ring, &cqe) == 0) {
            int cqe_data = cqe->user_data;
            int cqe_res = cqe->res;
            int cq_ready = io_uring_cq_ready(&ring);
            io_uring_cqe_seen(&ring, cqe);
            
            if (cqe_data == target_id) {
                #ifdef DEBUG_LOG
                printf("%s get self cqe, user_data %d, res %d, cq_ready: %d\n", str, cqe_data, cqe_res, cq_ready);
                #endif
                res = cqe_res;
                pthread_mutex_unlock(&cq_lock);
                // printf("%s free cq lock\n", str);
                break;
            }
            else {
                #ifdef DEBUG_LOG
                printf("%s get other cqe, user_data %d, res %d, want id: %d, cq_ready: %d\n", str, cqe_data, cqe_res, target_id, cq_ready);
                #endif
                has_results[cqe_data] = 1;
                results[cqe_data] = cqe_res;
            }
        }

        pthread_mutex_unlock(&cq_lock);
    }
    return res;
}

extern int32_t io_uring_do_sendmsg(int fd,
    const void* msg_name,
    socklen_t msg_namelen,
    const struct iovec* msg_iov,
    size_t msg_iovlen,
    const void* msg_control,
    size_t msg_controllen,
    int flags);

extern int32_t io_uring_do_recvmsg(int fd,
    void* msg_name,
    socklen_t msg_namelen,
    socklen_t* msg_namelen_recv,
    struct iovec* msg_iov,
    size_t msg_iovlen,
    void* msg_control,
    size_t msg_controllen,
    size_t* msg_controllen_recv,
    int* msg_flags_recv,
    int flags);

int do_read(int fd, const void* buf, size_t n) {
    struct iovec iov[1];
    iov[0].iov_base = buf;
    iov[0].iov_len = n;
    struct msghdr msg = { NULL, 0, iov, 1, NULL, 0, 0 };

    #ifdef USE_C_IO_URING
    int id = submit(fd, 0, &msg, IORING_OP_RECVMSG, __func__);
    int res = complete(id, __func__);
    #else
    socklen_t msg_namelen_recv;
    size_t msg_controllen_recv;
    int msg_flags_recv;
    int res = io_uring_do_recvmsg(
        fd, 
        msg.msg_name, msg.msg_namelen, &msg_namelen_recv,
        msg.msg_iov, msg.msg_iovlen, 
        msg.msg_control, msg.msg_controllen, &msg_controllen_recv,
        &msg_flags_recv, 0);
    #endif
   
    #ifdef DEBUG_LOG
    printf("%s cqe->res %d\n", __func__, res);
    #endif
    return res;
}

int do_write(int fd, const void* buf, size_t n) {
    struct iovec iov[1];
    iov[0].iov_base = buf;
    iov[0].iov_len = n;
    struct msghdr msg = { NULL, 0, iov, 1, NULL, 0, 0 };

    #ifdef USE_C_IO_URING
    int id = submit(fd, 0, &msg, IORING_OP_SENDMSG, __func__);
    int res = complete(id, __func__);
    #else
    int res = io_uring_do_sendmsg(
        fd, 
        msg.msg_name, msg.msg_namelen,
        msg.msg_iov, msg.msg_iovlen, 
        msg.msg_control, msg.msg_controllen,
        0);
    #endif
    
    #ifdef DEBUG_LOG
    printf("%s cqe->res %d\n", __func__, res);
    #endif
    return res;
}

int do_recv(int fd, const void* buf, size_t n, int flags) {
    struct iovec iov[1];
    iov[0].iov_base = buf;
    iov[0].iov_len = n;
    struct msghdr msg = { NULL, 0, iov, 1, NULL, 0, 0 };
    

    #ifdef USE_C_IO_URING
    int id = submit(fd, flags, &msg, IORING_OP_RECVMSG, __func__);
    int res = complete(id, __func__);
    #else
    socklen_t msg_namelen_recv;
    size_t msg_controllen_recv;
    int msg_flags_recv;
    int res = io_uring_do_recvmsg(
        fd, 
        msg.msg_name, msg.msg_namelen, &msg_namelen_recv,
        msg.msg_iov, msg.msg_iovlen, 
        msg.msg_control, msg.msg_controllen, &msg_controllen_recv,
        &msg_flags_recv, 0);
    #endif
   
    #ifdef DEBUG_LOG
    printf("%s cqe->res %d\n", __func__, res);
    #endif
    return res;
}

int do_send(int fd, const void* buf, size_t n, int flags) {
    struct iovec iov[1];
    iov[0].iov_base = buf;
    iov[0].iov_len = n;
    struct msghdr msg = { NULL, 0, iov, 1, NULL, 0, 0 };

    #ifdef USE_C_IO_URING
    int id = submit(fd, flags, &msg, IORING_OP_SENDMSG, __func__);
    int res = complete(id, __func__);
    #else
    int res = io_uring_do_sendmsg(
        fd, 
        msg.msg_name, msg.msg_namelen,
        msg.msg_iov, msg.msg_iovlen, 
        msg.msg_control, msg.msg_controllen,
        0);
    #endif
    
    #ifdef DEBUG_LOG
    printf("%s cqe->res %d\n", __func__, res);
    #endif
    return res;
}

int do_recvmsg(int fd, struct msghdr * msg, int flags) {
    if (msg->msg_iovlen == 0) {
        #ifdef DEBUG_LOG
        printf("%s res %d\n", __func__, 0);
        #endif
        return 0;
    }

    #ifdef USE_C_IO_URING
    int id = submit(fd, flags, msg, IORING_OP_RECVMSG, __func__);
    int res = complete(id, __func__);
    #else
    socklen_t msg_namelen_recv;
    size_t msg_controllen_recv;
    int msg_flags_recv;
    int res = io_uring_do_recvmsg(
        fd, 
        msg->msg_name, msg->msg_namelen, &msg_namelen_recv,
        msg->msg_iov, msg->msg_iovlen, 
        msg->msg_control, msg->msg_controllen, &msg_controllen_recv,
        &msg_flags_recv, 0);
    #endif
   
    #ifdef DEBUG_LOG
    printf("%s cqe->res %d\n", __func__, res);
    #endif
    return res;
}

int do_sendmsg(int fd, struct msghdr * msg, int flags) {
    if (msg->msg_iovlen == 0) {
        #ifdef DEBUG_LOG
        printf("%s res %d\n", __func__, 0);
        #endif
        return 0;
    }

    #ifdef USE_C_IO_URING
    int id = submit(fd, flags, msg, IORING_OP_SENDMSG, __func__);
    int res = complete(id, __func__);
    #else
    int res = io_uring_do_sendmsg(
        fd, 
        msg->msg_name, msg->msg_namelen,
        msg->msg_iov, msg->msg_iovlen, 
        msg->msg_control, msg->msg_controllen,
        0);
    #endif
    
    #ifdef DEBUG_LOG
    printf("%s cqe->res %d\n", __func__, res);
    #endif
    return res;
}

int connect_with_server(const char *addr_string, const char *port_string) {
    //"NULL" addr means connectionless, no need to connect to server
    if (strcmp(addr_string, "NULL") == 0) {
        return 0;
    }

    int ret = 0;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        THROW_ERROR("create socket error");
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons((uint16_t)strtol(port_string, NULL, 10));
    ret = inet_pton(AF_INET, addr_string, &servaddr.sin_addr);
    if (ret <= 0) {
        close(sockfd);
        THROW_ERROR("inet_pton error");
    }

    ret = connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
    if (ret < 0) {
        close(sockfd);
        THROW_ERROR("connect error");
    }

    return sockfd;
}

int client_neogotiate_msg(int server_fd, char *buf, int buf_size) {
    if (do_read(server_fd, buf, buf_size) < 0) {
        THROW_ERROR("read failed");
    }

    if (do_write(server_fd, RESPONSE, sizeof(RESPONSE)) < 0) {
        THROW_ERROR("write failed");
    }
    return 0;
}

int client_send(int server_fd, char *buf) {
    if (do_send(server_fd, buf, strlen(buf), 0) < 0) {
        THROW_ERROR("send msg error");
    }
    return 0;
}

int client_sendmsg(int server_fd, char *buf) {
    int ret = 0;
    struct msghdr msg;
    struct iovec iov[1];
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    iov[0].iov_base = buf;
    iov[0].iov_len = strlen(buf);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = 0;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    ret = do_sendmsg(server_fd, &msg, 0);
    if (ret <= 0) {
        THROW_ERROR("sendmsg failed");
    }

    msg.msg_iov = NULL;
    msg.msg_iovlen = 0;

    ret = do_sendmsg(server_fd, &msg, 0);
    if (ret != 0) {
        THROW_ERROR("empty sendmsg failed");
    }
    return ret;
}

int client_connectionless_sendmsg(char *buf) {
    int ret = 0;
    struct msghdr msg;
    struct iovec iov[1];
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(9900);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    msg.msg_name = &servaddr;
    msg.msg_namelen = sizeof(servaddr);
    iov[0].iov_base = buf;
    iov[0].iov_len = strlen(buf);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = 0;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) {
        THROW_ERROR("create socket error");
    }

    ret = do_sendmsg(server_fd, &msg, 0);
    if (ret <= 0) {
        THROW_ERROR("sendmsg failed");
    }
    return ret;
}

struct client_arg {
    int port;
    char addr_string[20];
    char port_string[20];
};

int client(void* arg) {
    struct client_arg* thread_arg = arg;

    int ret = 0;
    const int buf_size = 100;
    char buf[buf_size];
    int port = thread_arg->port;
    int server_fd = connect_with_server(thread_arg->addr_string, thread_arg->port_string);
    test_fd_client = server_fd;

    switch (port) {
        case 8800:
            client_neogotiate_msg(server_fd, buf, buf_size);
            break;
        case 8801:
            client_neogotiate_msg(server_fd, buf, buf_size);
            ret = client_send(server_fd, buf);
            break;
        case 8802:
            client_neogotiate_msg(server_fd, buf, buf_size);
            ret = client_sendmsg(server_fd, buf);
            break;
        case 8803:
            ret = client_connectionless_sendmsg(DEFAULT_MSG);
            break;
        default:
            ret = client_send(server_fd, DEFAULT_MSG);
    }

    close(server_fd);
    return ret;
}


int connect_with_child(int port, int *child_pid) {
    int ret = 0;
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        THROW_ERROR("create socket error");
    }
    int reuse = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        THROW_ERROR("setsockopt port to reuse failed");
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    ret = bind(listen_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
    if (ret < 0) {
        close(listen_fd);
        THROW_ERROR("bind socket failed");
    }

    ret = listen(listen_fd, 10);
    if (ret < 0) {
        close(listen_fd);
        THROW_ERROR("listen socket error");
    }

    char port_string[8];
    sprintf(port_string, "%d", port);
    
    struct client_arg* arg = malloc(sizeof(struct client_arg));
    arg->port = port;
    strcpy(arg->addr_string, "127.0.0.1");
    strcpy(arg->port_string, port_string);

    ret = pthread_create(&thread_id, NULL, client, (void *)arg);
    if (ret) {
        printf("unable to create thread, %d\n", ret);
    }

    int connected_fd = accept(listen_fd, (struct sockaddr *) NULL, NULL);
    if (connected_fd < 0) {
        close(listen_fd);
        THROW_ERROR("accept socket error");
    }

    close(listen_fd);
    return connected_fd;
}

int neogotiate_msg(int client_fd) {
    char buf[16];
    if (do_write(client_fd, ECHO_MSG, strlen(ECHO_MSG)) < 0) {
        THROW_ERROR("write failed");
    }

    if (do_read(client_fd, buf, sizeof(RESPONSE)) < 0) {
        THROW_ERROR("read failed");
    }

    if (strncmp(buf, RESPONSE, sizeof(RESPONSE)) != 0) {
        THROW_ERROR("msg recv mismatch");
    }
    return 0;
}

int server_recv(int client_fd) {
    const int buf_size = 32;
    char buf[buf_size];

    if (do_recv(client_fd, buf, buf_size, 0) <= 0) {
        THROW_ERROR("msg recv failed");
    }

    if (strncmp(buf, ECHO_MSG, strlen(ECHO_MSG)) != 0) {
        THROW_ERROR("msg recv mismatch");
    }
    return 0;
}

int server_recvmsg(int client_fd) {
    int ret = 0;
    const int buf_size = 10;
    char buf[3][buf_size];
    struct msghdr msg;
    struct iovec iov[3];

    msg.msg_name  = NULL;
    msg.msg_namelen  = 0;
    iov[0].iov_base = buf[0];
    iov[0].iov_len = buf_size;
    iov[1].iov_base = buf[1];
    iov[1].iov_len = buf_size;
    iov[2].iov_base = buf[2];
    iov[2].iov_len = buf_size;
    msg.msg_iov = iov;
    msg.msg_iovlen = 3;
    msg.msg_control = 0;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    ret = do_recvmsg(client_fd, &msg, 0);
    if (ret <= 0) {
        THROW_ERROR("recvmsg failed");
    } else {
        if (strncmp(buf[0], ECHO_MSG, buf_size) != 0 &&
                strstr(ECHO_MSG, buf[1]) != NULL &&
                strstr(ECHO_MSG, buf[2]) != NULL) {
            printf("recvmsg : %d, msg: %s,  %s, %s\n", ret, buf[0], buf[1], buf[2]);
            THROW_ERROR("msg recvmsg mismatch");
        }
    }
    msg.msg_iov = NULL;
    msg.msg_iovlen = 0;
    ret = do_recvmsg(client_fd, &msg, 0);
    if (ret != 0) {
        THROW_ERROR("recvmsg empty failed");
    }
    return ret;
}

int server_connectionless_recvmsg() {
    int ret = 0;
    const int buf_size = 1000;
    char buf[buf_size];
    struct msghdr msg;
    struct iovec iov[1];

    struct sockaddr_in servaddr;
    struct sockaddr_in clientaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&clientaddr, 0, sizeof(clientaddr));

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        THROW_ERROR("create socket error");
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(9900);
    ret = bind(sock, (struct sockaddr *) &servaddr, sizeof(servaddr));
    if (ret < 0) {
        close(sock);
        THROW_ERROR("bind socket failed");
    }

    msg.msg_name  = &clientaddr;
    msg.msg_namelen  = sizeof(clientaddr);
    iov[0].iov_base = buf;
    iov[0].iov_len = buf_size;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = 0;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    ret = do_recvmsg(sock, &msg, 0);
    if (ret <= 0) {
        THROW_ERROR("recvmsg failed");
    } else {
        if (strncmp(buf, DEFAULT_MSG, strlen(DEFAULT_MSG)) != 0) {
            printf("recvmsg : %d, msg: %s\n", ret, buf);
            THROW_ERROR("msg recvmsg mismatch");
        } else {
            inet_ntop(AF_INET, &clientaddr.sin_addr,
                      buf, sizeof(buf));
            if (strcmp(buf, "127.0.0.1") != 0) {
                printf("from port %d and address %s\n", ntohs(clientaddr.sin_port), buf);
                THROW_ERROR("client addr mismatch");
            }
        }
    }
    return ret;
}

int wait_for_child_exit(int child_pid) {
    int status = 0;
    if (wait4(child_pid, &status, 0, NULL) < 0) {
        THROW_ERROR("failed to wait4 the child process");
    }
    return 0;
}

int test_read_write() {
    fprintf(stderr, "----------------------------------test_read_write---------------------------------\n");
    int ret = 0;
    int child_pid = 0;
    int client_fd = connect_with_child(8800, &child_pid);
    
    if (client_fd < 0) {
        THROW_ERROR("connect failed");
    } else {
        ret = neogotiate_msg(client_fd);
    }

    pthread_join(thread_id, NULL);

    return ret;
}

int test_send_recv() {
    fprintf(stderr, "----------------------------------test_send_recv---------------------------------\n");
    int ret = 0;
    int child_pid = 0;
    int client_fd = connect_with_child(8801, &child_pid);
    if (client_fd < 0) {
        THROW_ERROR("connect failed");
    }

    if (neogotiate_msg(client_fd) < 0) {
        THROW_ERROR("neogotiate failed");
    }

    ret = server_recv(client_fd);
    if (ret < 0) { return -1; }

    pthread_join(thread_id, NULL);

    return ret;
}

int test_sendmsg_recvmsg() {
    fprintf(stderr, "----------------------------------test_sendmsg_recvmsg---------------------------------\n");
    int ret = 0;
    int child_pid = 0;
    int client_fd = connect_with_child(8802, &child_pid);
    if (client_fd < 0) {
        THROW_ERROR("connect failed");
    }

    if (neogotiate_msg(client_fd) < 0) {
        THROW_ERROR("neogotiate failed");
    }

    ret = server_recvmsg(client_fd);
    if (ret < 0) { return -1; }

    pthread_join(thread_id, NULL);

    return ret;
}

int test_sendmsg_recvmsg_connectionless() {
    fprintf(stderr, "----------------------------------test_sendmsg_recvmsg_connectionless---------------------------------\n");
    int ret = 0;
    int child_pid = 0;

    struct client_arg* arg = malloc(sizeof(struct client_arg));
    arg->port = 8803;
    strcpy(arg->addr_string, "NULL");
    strcpy(arg->port_string, "8803");

    ret = pthread_create(&thread_id, NULL, client, (void *)arg);
    if (ret) {
        printf("unable to create thread, %d\n", ret);
    }

    ret = server_connectionless_recvmsg();
    if (ret < 0) { return -1; }

    pthread_join(thread_id, NULL);

    return ret;
}

int test_fcntl_setfl_and_getfl() {
    int ret = 0;
    int child_pid = 0;
    int client_fd = -1;
    int original_flags, actual_flags;

    client_fd = connect_with_child(8804, &child_pid);
    if (client_fd < 0) {
        THROW_ERROR("connect failed");
    }
    original_flags = fcntl(client_fd, F_GETFL, 0);
    if (original_flags < 0) {
        THROW_ERROR("fcntl getfl failed");
    }

    ret = fcntl(client_fd, F_SETFL, original_flags | O_NONBLOCK);
    if (ret < 0) {
        THROW_ERROR("fcntl setfl failed");
    }

    actual_flags = fcntl(client_fd, F_GETFL, 0);
    if (actual_flags != (original_flags | O_NONBLOCK)) {
        THROW_ERROR("check the getfl value after setfl failed");
    }

    ret = wait_for_child_exit(child_pid);

    return ret;
}

int test_poll_events_unchanged() {
    int socks[2], ret;
    socks[0] = socket(AF_INET, SOCK_STREAM, 0);
    socks[1] = socket(AF_INET, SOCK_STREAM, 0);
    struct pollfd pollfds[] = {
        { .fd = socks[0], .events = POLLIN },
        { .fd = socks[1], .events = POLLIN },
    };

    ret = poll(pollfds, 2, 0);
    if (ret < 0) {
        THROW_ERROR("poll error");
    }

    if (pollfds[0].fd != socks[0] ||
            pollfds[0].events != POLLIN ||
            pollfds[1].fd != socks[1] ||
            pollfds[1].events != POLLIN) {
        THROW_ERROR("fd and events of pollfd should remain unchanged");
    }
    return 0;
}

int test_poll() {
    int child_pid = 0;
    int client_fd = connect_with_child(8805, &child_pid);
    if (client_fd < 0) {
        THROW_ERROR("connect failed");
    }

    struct pollfd polls[] = {
        { .fd = client_fd, .events = POLLIN }
    };
    int ret = poll(polls, 1, -1);
    if (ret <= 0) {
        THROW_ERROR("poll error");
    }

    if (polls[0].revents & POLLIN) {
        ssize_t count;
        char buf[512];
        if ((count = read(client_fd, buf, sizeof buf)) != 0) {
            if (strcmp(buf, DEFAULT_MSG) != 0) {
                printf(buf);
                THROW_ERROR("msg mismatched");
            }
        } else {
            THROW_ERROR("read error");
        }
    } else {
        THROW_ERROR("unexpected return events");
    }

    int status = 0;
    if (wait4(child_pid, &status, 0, NULL) < 0) {
        THROW_ERROR("failed to wait4 the child process");
    }
    close(client_fd);
    return 0;
}


int main(int argc, const char *argv[]) {
    #ifdef USE_C_IO_URING
    init_io_uring();
    #endif
    test_read_write();
    #ifdef USE_C_IO_URING
    destroy_io_uring();
    #endif

    #ifdef USE_C_IO_URING
    init_io_uring();
    #endif
    test_send_recv();
    #ifdef USE_C_IO_URING
    destroy_io_uring();
    #endif

    #ifdef USE_C_IO_URING
    init_io_uring();
    #endif
    test_sendmsg_recvmsg();
    #ifdef USE_C_IO_URING
    destroy_io_uring();
    #endif

    #ifdef USE_C_IO_URING
    init_io_uring();
    #endif
    test_sendmsg_recvmsg_connectionless();
    #ifdef USE_C_IO_URING
    destroy_io_uring();
    #endif

    // test_fcntl_setfl_and_getfl();
    // test_poll();
    // test_poll_events_unchanged();
}
