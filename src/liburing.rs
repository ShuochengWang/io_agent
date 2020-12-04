use super::*;
use io_uring::*;

lazy_static! {
    pub(crate) static ref SQ_LOCK: Mutex<bool> = Mutex::new(true);
    static ref ID_RES_MAP: Mutex<HashMap<u64, i32>> = Mutex::new(HashMap::new());
}

#[repr(C)]
#[derive(Debug)]
pub struct IoUringSq {
    pub(crate) khead: *const atomic::AtomicU32,
    pub(crate) ktail: *const atomic::AtomicU32,
    pub(crate) kring_mask: *const u32,
    pub(crate) kring_entries: *const u32,
    pub(crate) kflags: *const atomic::AtomicU32,
    pub(crate) kdropped: *const atomic::AtomicU32,
    pub(crate) array: *mut u32,
    pub(crate) sqes: *mut io_uring_sqe,

    pub(crate) sqe_head: u32,
    pub(crate) sqe_tail: u32,

    pub(crate) ring_sz: u64,
    pub(crate) ring_ptr: *const c_void,

    pub(crate) pad: [u32; 4usize],
}

impl IoUringSq {
    #[inline]
    pub fn get_khead_acquire(&self) -> u32 {
        unsafe { (*self.khead).load(atomic::Ordering::Acquire) }
    }

    #[inline]
    pub fn get_khead(&self) -> u32 {
        unsafe { (*self.khead).load(atomic::Ordering::Relaxed) }
    }

    #[inline]
    pub fn get_ktail_acquire(&self) -> u32 {
        unsafe { (*self.ktail).load(atomic::Ordering::Acquire) }
    }

    #[inline]
    pub fn get_ktail(&self) -> u32 {
        unsafe { (*self.ktail).load(atomic::Ordering::Relaxed) }
    }

    #[inline]
    pub fn get_kring_mask(&self) -> u32 {
        unsafe { *self.kring_mask }
    }

    #[inline]
    pub fn get_kring_entries(&self) -> u32 {
        unsafe { *self.kring_entries }
    }

    #[inline]
    pub fn get_kflags_acquire(&self) -> u32 {
        unsafe { (*self.kflags).load(atomic::Ordering::Acquire) }
    }

    #[inline]
    pub fn set_ktail_release(&self, value: u32) {
        unsafe {
            (*self.ktail).store(value, atomic::Ordering::Release);
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct IoUringCq {
    pub(crate) khead: *const atomic::AtomicU32,
    pub(crate) ktail: *const atomic::AtomicU32,
    pub(crate) kring_mask: *const u32,
    pub(crate) kring_entries: *const u32,
    pub(crate) kflags: *const atomic::AtomicU32,
    pub(crate) koverflow: *const atomic::AtomicU32,
    pub(crate) cqes: *mut io_uring_cqe,

    pub(crate) ring_sz: u64,
    pub(crate) ring_ptr: *const c_void,

    pub(crate) pad: [u32; 4usize],
}

impl IoUringCq {
    #[inline]
    pub fn get_khead_acquire(&self) -> u32 {
        unsafe { (*self.khead).load(atomic::Ordering::Acquire) }
    }

    #[inline]
    pub fn get_khead(&self) -> u32 {
        unsafe { (*self.khead).load(atomic::Ordering::Relaxed) }
    }

    #[inline]
    pub fn get_ktail_acquire(&self) -> u32 {
        unsafe { (*self.ktail).load(atomic::Ordering::Acquire) }
    }

    #[inline]
    pub fn get_ktail(&self) -> u32 {
        unsafe { (*self.ktail).load(atomic::Ordering::Relaxed) }
    }

    #[inline]
    pub fn get_kring_mask(&self) -> u32 {
        unsafe { *self.kring_mask }
    }

    #[inline]
    pub fn set_khead_release(&self, value: u32) {
        unsafe {
            (*self.khead).store(value, atomic::Ordering::Release);
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct IoUring {
    pub(crate) sq: IoUringSq,
    pub(crate) cq: IoUringCq,
    pub(crate) flags: u32,
    pub(crate) ring_fd: i32,

    pub(crate) features: u32,
    pub(crate) pad: [u32; 3usize],
}

impl IoUring {
    pub fn io_uring_get_sqe(&mut self) -> Result<*mut io_uring_sqe, ()> {
        let next = self.sq.sqe_tail + 1;
        let mask = self.sq.get_kring_mask();
        if next - self.sq.get_khead_acquire() <= self.sq.get_kring_entries() {
            let sqe_ptr = unsafe { self.sq.sqes.offset((self.sq.sqe_tail & mask) as isize) };
            self.sq.sqe_tail = next;

            return Ok(sqe_ptr);
        }

        println!("io_uring_get_sqe failed");
        return Err(());
    }

    pub fn io_uring_submit(&mut self) -> i32 {
        let submitted = self.io_uring_flush_sq();

        let mut flags: u32 = 0;
        let mut ret: i32 = 0;

        if self.sq_ring_needs_enter(&mut flags) {
            unsafe {
                occlum_ocall_io_uring_enter(self.ring_fd, submitted, 0, flags);
            }
        } else {
            ret = submitted as i32;
        }

        ret
    }

    pub fn io_uring_get_cqe_res(&self, req_id: u64) -> i32 {
        loop {
            // println!(" try get lock");
            let mut map = ID_RES_MAP.lock().unwrap();
            // println!(" get lock success. {:?}", map);

            if let Some(&cqe_res) = map.get(&req_id) {
                map.remove(&req_id);
                return cqe_res;
            } else {
                let mut head: u32 = self.cq.get_khead();
                if head != self.cq.get_ktail_acquire() {
                    let mask = self.cq.get_kring_mask();
                    let cqe_ptr = unsafe { self.cq.cqes.offset((head & mask) as isize) };
                    let cqe_id = unsafe { (*cqe_ptr).user_data };
                    let cqe_res = unsafe { (*cqe_ptr).res };

                    self.cq.set_khead_release(self.cq.get_khead() + 1);
                    if cqe_id == req_id {
                        return cqe_res;
                    } else {
                        println!("get others data, id: {}, res: {}", cqe_id, cqe_res);
                        map.insert(cqe_id, cqe_res);
                    }
                }
                // todo: cq overflow flush
            }

            drop(map);
        }
    }

    fn io_uring_flush_sq(&mut self) -> u32 {
        let mask = self.sq.get_kring_mask();
        let mut ktail;
        let mut to_submit;

        if self.sq.sqe_head == self.sq.sqe_tail {
            ktail = self.sq.get_ktail();
            return ktail - self.sq.get_khead();
        }

        ktail = self.sq.get_ktail();
        to_submit = self.sq.sqe_tail - self.sq.sqe_head;
        while to_submit > 0 {
            unsafe {
                *self.sq.array.offset((ktail & mask) as isize) = self.sq.sqe_head & mask;
            }
            ktail += 1;
            self.sq.sqe_head += 1;
            to_submit -= 1;
        }

        self.sq.set_ktail_release(ktail);

        return ktail - self.sq.get_khead();
    }

    fn sq_ring_needs_enter(&self, flags: &mut u32) -> bool {
        if (self.flags & IORING_SETUP_SQPOLL) == 0 {
            return true;
        }
        if (self.sq.get_kflags_acquire() & IORING_SQ_NEED_WAKEUP) != 0 {
            *flags |= IORING_ENTER_SQ_WAKEUP;
            return true;
        }

        return false;
    }
}

unsafe fn io_uring_prep_rw(
    op: u32,
    sqe_ptr: *mut io_uring_sqe,
    fd: i32,
    addr: u64,
    len: u32,
    offset: u64,
    user_data: u64,
    sqe_flags: u8,
) {
    (*sqe_ptr).opcode = op as u8;
    (*sqe_ptr).flags = sqe_flags;
    (*sqe_ptr).ioprio = 0;
    (*sqe_ptr).fd = fd;
    (*sqe_ptr).__bindgen_anon_1.off = offset;
    (*sqe_ptr).__bindgen_anon_2.addr = addr;
    (*sqe_ptr).len = len;
    (*sqe_ptr).__bindgen_anon_3.rw_flags = 0;
    (*sqe_ptr).user_data = user_data;
    (*sqe_ptr).__bindgen_anon_4.__pad2[0] = 0;
    (*sqe_ptr).__bindgen_anon_4.__pad2[1] = 0;
    (*sqe_ptr).__bindgen_anon_4.__pad2[2] = 0;
}

pub fn io_uring_prep_recvmsg(
    sqe_ptr: *mut io_uring_sqe,
    fd: i32,
    msg_ptr: *const msghdr,
    flags: u32,
    user_data: u64,
    sqe_flags: u8,
) {
    unsafe {
        io_uring_prep_rw(
            IORING_OP_RECVMSG,
            sqe_ptr,
            fd,
            msg_ptr as u64,
            1,
            0,
            user_data,
            sqe_flags,
        );
        (*sqe_ptr).__bindgen_anon_3.msg_flags = flags;
    }
}

pub fn io_uring_prep_sendmsg(
    sqe_ptr: *mut io_uring_sqe,
    fd: i32,
    msg_ptr: *const msghdr,
    flags: u32,
    user_data: u64,
    sqe_flags: u8,
) {
    unsafe {
        io_uring_prep_rw(
            IORING_OP_SENDMSG,
            sqe_ptr,
            fd,
            msg_ptr as u64,
            1,
            0,
            user_data,
            sqe_flags,
        );
        (*sqe_ptr).__bindgen_anon_3.msg_flags = flags;
    }
}

extern "C" {
    fn occlum_ocall_io_uring_enter(fd: i32, to_submit: u32, min_complete: u32, flags: u32) -> i32;
}
