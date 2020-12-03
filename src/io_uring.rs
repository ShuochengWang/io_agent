/* source file: https://github.com/axboe/liburing/blob/master/src/include/liburing/io_uring.h
   liburing version: commit 36026fcb261a718f81858d6dc760a8bf50d594b8
   
   Convert io_uring.h to io_uring.rs by rust-bindgen and then refactor code. 
*/

#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::std::marker::PhantomData<T>, [T; 0]);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub const fn new() -> Self {
        __IncompleteArrayField(::std::marker::PhantomData, [])
    }
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self as *const _ as *const T
    }
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self as *mut _ as *mut T
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::std::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}

impl<T> ::std::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}

pub const IORING_SETUP_IOPOLL: u32 = 1;
pub const IORING_SETUP_SQPOLL: u32 = 2;
pub const IORING_SETUP_SQ_AFF: u32 = 4;
pub const IORING_SETUP_CQSIZE: u32 = 8;
pub const IORING_SETUP_CLAMP: u32 = 16;
pub const IORING_SETUP_ATTACH_WQ: u32 = 32;
pub const IORING_SETUP_R_DISABLED: u32 = 64;
pub const IORING_FSYNC_DATASYNC: u32 = 1;
pub const IORING_TIMEOUT_ABS: u32 = 1;
pub const IORING_CQE_F_BUFFER: u32 = 1;
pub const IORING_OFF_SQ_RING: u32 = 0;
pub const IORING_OFF_CQ_RING: u32 = 134217728;
pub const IORING_OFF_SQES: u32 = 268435456;
pub const IORING_SQ_NEED_WAKEUP: u32 = 1;
pub const IORING_SQ_CQ_OVERFLOW: u32 = 2;
pub const IORING_CQ_EVENTFD_DISABLED: u32 = 1;
pub const IORING_ENTER_GETEVENTS: u32 = 1;
pub const IORING_ENTER_SQ_WAKEUP: u32 = 2;
pub const IORING_ENTER_SQ_WAIT: u32 = 4;
pub const IORING_ENTER_EXT_ARG: u32 = 8;
pub const IORING_FEAT_SINGLE_MMAP: u32 = 1;
pub const IORING_FEAT_NODROP: u32 = 2;
pub const IORING_FEAT_SUBMIT_STABLE: u32 = 4;
pub const IORING_FEAT_RW_CUR_POS: u32 = 8;
pub const IORING_FEAT_CUR_PERSONALITY: u32 = 16;
pub const IORING_FEAT_FAST_POLL: u32 = 32;
pub const IORING_FEAT_POLL_32BITS: u32 = 64;
pub const IORING_FEAT_SQPOLL_NONFIXED: u32 = 128;
pub const IORING_FEAT_EXT_ARG: u32 = 256;
pub const IO_URING_OP_SUPPORTED: u32 = 1;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct io_uring_sqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub __bindgen_anon_1: io_uring_sqe__bindgen_ty_1,
    pub __bindgen_anon_2: io_uring_sqe__bindgen_ty_2,
    pub len: u32,
    pub __bindgen_anon_3: io_uring_sqe__bindgen_ty_3,
    pub user_data: u64,
    pub __bindgen_anon_4: io_uring_sqe__bindgen_ty_4,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union io_uring_sqe__bindgen_ty_1 {
    pub off: u64,
    pub addr2: u64,
    _bindgen_union_align: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union io_uring_sqe__bindgen_ty_2 {
    pub addr: u64,
    pub splice_off_in: u64,
    _bindgen_union_align: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union io_uring_sqe__bindgen_ty_3 {
    pub rw_flags: i32,
    pub fsync_flags: u32,
    pub poll_events: u16,
    pub poll32_events: u32,
    pub sync_range_flags: u32,
    pub msg_flags: u32,
    pub timeout_flags: u32,
    pub accept_flags: u32,
    pub cancel_flags: u32,
    pub open_flags: u32,
    pub statx_flags: u32,
    pub fadvise_advice: u32,
    pub splice_flags: u32,
    pub rename_flags: u32,
    pub unlink_flags: u32,
    _bindgen_union_align: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union io_uring_sqe__bindgen_ty_4 {
    pub __bindgen_anon_1: io_uring_sqe__bindgen_ty_4__bindgen_ty_1,
    pub __pad2: [u64; 3usize],
    _bindgen_union_align: [u64; 3usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct io_uring_sqe__bindgen_ty_4__bindgen_ty_1 {
    pub __bindgen_anon_1: io_uring_sqe__bindgen_ty_4__bindgen_ty_1__bindgen_ty_1,
    pub personality: u16,
    pub splice_fd_in: i32,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union io_uring_sqe__bindgen_ty_4__bindgen_ty_1__bindgen_ty_1 {
    pub buf_index: u16,
    pub buf_group: u16,
    _bindgen_union_align: [u8; 2usize],
}


pub const IOSQE_FIXED_FILE_BIT: u32 = 0;
pub const IOSQE_IO_DRAIN_BIT: u32 = 1;
pub const IOSQE_IO_LINK_BIT: u32 = 2;
pub const IOSQE_IO_HARDLINK_BIT: u32 = 3;
pub const IOSQE_ASYNC_BIT: u32 = 4;
pub const IOSQE_BUFFER_SELECT_BIT: u32 = 5;
pub const IOSQE_FIXED_FILE: u8 = 1 << IOSQE_FIXED_FILE_BIT;
pub const IOSQE_IO_DRAIN: u8 = 1 << IOSQE_IO_DRAIN_BIT;
pub const IOSQE_IO_LINK: u8 = 1 << IOSQE_IO_LINK_BIT;
pub const IOSQE_IO_HARDLINK: u8 = 1 << IOSQE_IO_HARDLINK_BIT;
pub const IOSQE_ASYNC: u8 = 1 << IOSQE_ASYNC_BIT;
pub const IOSQE_BUFFER_SELECT: u8 = 1 << IOSQE_BUFFER_SELECT_BIT;
pub const IORING_OP_NOP: u32 = 0;
pub const IORING_OP_READV: u32 = 1;
pub const IORING_OP_WRITEV: u32 = 2;
pub const IORING_OP_FSYNC: u32 = 3;
pub const IORING_OP_READ_FIXED: u32 = 4;
pub const IORING_OP_WRITE_FIXED: u32 = 5;
pub const IORING_OP_POLL_ADD: u32 = 6;
pub const IORING_OP_POLL_REMOVE: u32 = 7;
pub const IORING_OP_SYNC_FILE_RANGE: u32 = 8;
pub const IORING_OP_SENDMSG: u32 = 9;
pub const IORING_OP_RECVMSG: u32 = 10;
pub const IORING_OP_TIMEOUT: u32 = 11;
pub const IORING_OP_TIMEOUT_REMOVE: u32 = 12;
pub const IORING_OP_ACCEPT: u32 = 13;
pub const IORING_OP_ASYNC_CANCEL: u32 = 14;
pub const IORING_OP_LINK_TIMEOUT: u32 = 15;
pub const IORING_OP_CONNECT: u32 = 16;
pub const IORING_OP_FALLOCATE: u32 = 17;
pub const IORING_OP_OPENAT: u32 = 18;
pub const IORING_OP_CLOSE: u32 = 19;
pub const IORING_OP_FILES_UPDATE: u32 = 20;
pub const IORING_OP_STATX: u32 = 21;
pub const IORING_OP_READ: u32 = 22;
pub const IORING_OP_WRITE: u32 = 23;
pub const IORING_OP_FADVISE: u32 = 24;
pub const IORING_OP_MADVISE: u32 = 25;
pub const IORING_OP_SEND: u32 = 26;
pub const IORING_OP_RECV: u32 = 27;
pub const IORING_OP_OPENAT2: u32 = 28;
pub const IORING_OP_EPOLL_CTL: u32 = 29;
pub const IORING_OP_SPLICE: u32 = 30;
pub const IORING_OP_PROVIDE_BUFFERS: u32 = 31;
pub const IORING_OP_REMOVE_BUFFERS: u32 = 32;
pub const IORING_OP_TEE: u32 = 33;
pub const IORING_OP_SHUTDOWN: u32 = 34;
pub const IORING_OP_RENAMEAT: u32 = 35;
pub const IORING_OP_UNLINKAT: u32 = 36;
pub const IORING_OP_LAST: u32 = 37;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct io_uring_cqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

pub const IORING_CQE_BUFFER_SHIFT: u32 = 16;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct io_sqring_offsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub resv2: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct io_cqring_offsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub resv2: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct io_uring_params {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3usize],
    pub sq_off: io_sqring_offsets,
    pub cq_off: io_cqring_offsets,
}

pub const IORING_REGISTER_BUFFERS: u32 = 0;
pub const IORING_UNREGISTER_BUFFERS: u32 = 1;
pub const IORING_REGISTER_FILES: u32 = 2;
pub const IORING_UNREGISTER_FILES: u32 = 3;
pub const IORING_REGISTER_EVENTFD: u32 = 4;
pub const IORING_UNREGISTER_EVENTFD: u32 = 5;
pub const IORING_REGISTER_FILES_UPDATE: u32 = 6;
pub const IORING_REGISTER_EVENTFD_ASYNC: u32 = 7;
pub const IORING_REGISTER_PROBE: u32 = 8;
pub const IORING_REGISTER_PERSONALITY: u32 = 9;
pub const IORING_UNREGISTER_PERSONALITY: u32 = 10;
pub const IORING_REGISTER_RESTRICTIONS: u32 = 11;
pub const IORING_REGISTER_ENABLE_RINGS: u32 = 12;
pub const IORING_REGISTER_LAST: u32 = 13;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct io_uring_files_update {
    pub offset: u32,
    pub resv: u32,
    pub fds: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct io_uring_probe_op {
    pub op: u8,
    pub resv: u8,
    pub flags: u16,
    pub resv2: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct io_uring_probe {
    pub last_op: u8,
    pub ops_len: u8,
    pub resv: u16,
    pub resv2: [u32; 3usize],
    pub ops: __IncompleteArrayField<io_uring_probe_op>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct io_uring_restriction {
    pub opcode: u16,
    pub __bindgen_anon_1: io_uring_restriction__bindgen_ty_1,
    pub resv: u8,
    pub resv2: [u32; 3usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union io_uring_restriction__bindgen_ty_1 {
    pub register_op: u8,
    pub sqe_op: u8,
    pub sqe_flags: u8,
    _bindgen_union_align: u8,
}

pub const IORING_RESTRICTION_REGISTER_OP: u32 = 0;
pub const IORING_RESTRICTION_SQE_OP: u32 = 1;
pub const IORING_RESTRICTION_SQE_FLAGS_ALLOWED: u32 = 2;
pub const IORING_RESTRICTION_SQE_FLAGS_REQUIRED: u32 = 3;
pub const IORING_RESTRICTION_LAST: u32 = 4;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct io_uring_getevents_arg {
    pub sigmask: u64,
    pub sigmask_sz: u32,
    pub pad: u32,
    pub ts: u64,
}