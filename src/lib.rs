#![crate_type = "staticlib"]

extern crate libc;
#[macro_use]
extern crate lazy_static;

use libc::c_int;
use libc::c_void;
use libc::msghdr;
use libc::size_t;
use std::alloc::Layout;
use std::assert;
use std::collections::HashMap;
use std::ptr;
use std::sync::{atomic, Mutex};

mod io_uring;
mod io_uring_allocator;
mod liburing;

use io_uring::*;
use io_uring_allocator::*;
use liburing::*;

const IO_URING_SIZE: usize = 1024;
const IO_URING_FILE_SET_SIZE: usize = 16;
const IO_URING_BUFFER_SIZE: usize = 1024 * 1024 * 64;

#[no_mangle]
pub extern "C" fn io_uring_do_sendmsg(
    fd: c_int,
    msg_name: *const c_void,
    msg_namelen: libc::socklen_t,
    msg_iov: *const libc::iovec,
    msg_iovlen: size_t,
    msg_control: *const c_void,
    msg_controllen: size_t,
    flags: c_int,
    msg_ptr_test: *mut msghdr,
) -> i32 {
    if let Ok(retval) = IO_AGENT.io_uring_sendmsg(
        fd,
        msg_name,
        msg_namelen,
        msg_iov,
        msg_iovlen,
        msg_control,
        msg_controllen,
        flags,
        msg_ptr_test,
    ) {
        retval as i32
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn io_uring_do_recvmsg(
    fd: c_int,
    msg_name: *mut c_void,
    msg_namelen: libc::socklen_t,
    msg_namelen_recv: *mut libc::socklen_t,
    msg_iov: *mut libc::iovec,
    msg_iovlen: size_t,
    msg_control: *mut c_void,
    msg_controllen: size_t,
    msg_controllen_recv: *mut size_t,
    msg_flags_recv: *mut c_int,
    flags: c_int,
    msg_ptr_test: *mut msghdr,
) -> i32 {
    if let Ok(retval) = IO_AGENT.io_uring_recvmsg(
        fd,
        msg_name,
        msg_namelen,
        msg_namelen_recv,
        msg_iov,
        msg_iovlen,
        msg_control,
        msg_controllen,
        msg_controllen_recv,
        msg_flags_recv,
        flags,
        msg_ptr_test,
    ) {
        retval as i32
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn rust_clear_register_files() {
    IO_AGENT.io_uring_unregister_all_files();
}

pub struct IoAgent {
    io_uring_addr: u64,
    io_uring: *mut IoUring,
    inc_id: atomic::AtomicU64,
    fds: Mutex<Vec<i32>>,
    pub allocator: IoUringAllocator,
}

impl IoAgent {
    pub fn new(ring_size: usize) -> Self {
        println!("init IoAgent");

        // use wrapper C directly
        unsafe {
            init_io_uring2();
        }
        return Self {
            io_uring_addr: 0,
            io_uring: ptr::null::<IoUring>() as *mut IoUring,
            inc_id: atomic::AtomicU64::new(0),
            fds: Mutex::new(Vec::new()),
            allocator: IoUringAllocator::empty_alloc(),
        };

        let mut io_uring_addr: u64 = unsafe { occlum_ocall_io_uring_init(ring_size as u32) };

        if let Ok(alloc) = IoUringAllocator::new(IO_URING_BUFFER_SIZE) {
            Self {
                io_uring_addr: io_uring_addr,
                io_uring: io_uring_addr as *mut IoUring,
                inc_id: atomic::AtomicU64::new(0),
                fds: Mutex::new(Vec::new()),
                allocator: alloc,
            }
        } else {
            Self {
                io_uring_addr: io_uring_addr,
                io_uring: io_uring_addr as *mut IoUring,
                inc_id: atomic::AtomicU64::new(0),
                fds: Mutex::new(Vec::new()),
                allocator: IoUringAllocator::empty_alloc(),
            }
        }
    }

    fn io_uring_register_files_helper(&self, fd: c_int) -> Result<usize, ()> {
        let mut fds_guard = self.fds.lock().unwrap();

        if fds_guard.is_empty() {
            fds_guard.resize(IO_URING_FILE_SET_SIZE, -1);
            fds_guard[0] = fd;
            let fds_ptr = fds_guard.as_slice().as_ptr();
            let fds_len = fds_guard.as_slice().len();

            let mut ret = unsafe {
                occlum_ocall_io_uring_register_files(
                    self.io_uring_addr,
                    fds_ptr as *const i32,
                    fds_len as u32,
                )
            };
            println!("fd: {}, index: 0, fds: {:?}, ret: {}", fd, fds_guard, ret);

            if ret != 0 {
                println!("occlum_ocall_io_uring_register_files register file failed");
                return Err(());
            }
            return Ok(0);
        } else if let Some(fd_idx) = fds_guard.iter().position(|&x| x == fd) {
            println!("fd: {}, index: {}", fd, fd_idx);
            return Ok(fd_idx);
        } else if let Some(fd_idx) = fds_guard.iter().position(|&x| x == -1) {
            fds_guard[fd_idx] = fd;

            let mut ret =
                unsafe { occlum_ocall_io_uring_update_file(self.io_uring_addr, fd, fd_idx as u32) };
            println!(
                "fd: {}, index: {}, fds: {:?}, ret: {}",
                fd, fd_idx, fds_guard, ret
            );

            if ret != 1 {
                println!("occlum_ocall_io_uring_register_files update file failed");
                return Err(());
            }
            return Ok(fd_idx);
        } else {
            println!("io_uring file set is full!");
            return Err(());
        }
    }

    pub fn io_uring_unregister_files_helper(&self, fd: c_int) {
        let mut fds_guard = self.fds.lock().unwrap();
        if let Some(fd_idx) = fds_guard.iter().position(|&x| x == fd) {
            let empty_fd = -1;
            fds_guard[fd_idx] = empty_fd;
            let mut ret = unsafe {
                occlum_ocall_io_uring_update_file(self.io_uring_addr, empty_fd, fd_idx as u32)
            };
            if ret != 1 {
                println!(
                    "occlum_ocall_io_uring_update_file error! fd: {}, index: {}, ret: {}",
                    fd, fd_idx, ret
                );
            } else {
                println!(
                    "io_uring_unregister_files_helper success, fd: {}, index: {}, fds: {:?}",
                    fd, fd_idx, fds_guard
                );
            }
        }
    }

    pub fn io_uring_unregister_all_files(&self) {
        // use wrapper C directly
        unsafe {
            c_clear_register_files2();
        }
        return;

        let mut fds_guard = self.fds.lock().unwrap();
        fds_guard
            .iter()
            .enumerate()
            .filter(|&(i, x)| *x != -1)
            .for_each(|(i, x)| {
                let empty_fd = -1;
                let mut ret = unsafe {
                    occlum_ocall_io_uring_update_file(self.io_uring_addr, empty_fd, i as u32)
                };
                if ret != 1 {
                    println!(
                        "io_uring_unregister_all_files error! fd: {}, index: {}, ret: {}",
                        i, x, ret
                    );
                }
            });
        for elem in fds_guard.iter_mut() {
            *elem = -1;
        }
        println!("io_uring_unregister_all_files fds: {:?}", fds_guard);
    }

    pub fn io_uring_sendmsg(
        &self,
        fd: c_int,
        msg_name: *const c_void,
        msg_namelen: libc::socklen_t,
        msg_iov: *const libc::iovec,
        msg_iovlen: size_t,
        msg_control: *const c_void,
        msg_controllen: size_t,
        flags: c_int,
        msg_ptr_test: *mut msghdr,
    ) -> Result<isize, ()> {
        println!("io_uring_sendmsg, host_fd: {}, flags: {}, name {:?}, len {}, iov {:?}, len {}, control {:?}, len {}", 
            fd, flags, msg_name, msg_namelen, msg_iov, msg_iovlen, msg_control, msg_controllen);

        // use wrapper C directly
        let bytes_sent = unsafe { do_sendmsg2(fd, msg_ptr_test, flags) };
        println!("sendmsg cqe res {}, fd: {}", bytes_sent, fd);
        return Ok(bytes_sent as isize);

        let u_msghdr = self
            .allocator
            .new_align_slice_mut(
                std::mem::size_of::<msghdr>(),
                Layout::new::<msghdr>().align(),
            )?
            .as_mut_ptr();
        let mut msghdr_ptr = u_msghdr as *mut msghdr;

        if msg_name == ptr::null() {
            unsafe {
                (*msghdr_ptr).msg_name = ptr::null::<c_void>() as *mut c_void;
            }
        } else {
            let u_name_slice = self
                .allocator
                .new_align_slice_mut(msg_namelen as usize, 8)?;
            let name_slice =
                unsafe { std::slice::from_raw_parts(msg_name as *const u8, msg_namelen as usize) };
            u_name_slice.copy_from_slice(name_slice);
            unsafe { (*msghdr_ptr).msg_name = u_name_slice.as_mut_ptr() as *mut c_void }
        }

        if msg_control == ptr::null() {
            unsafe {
                (*msghdr_ptr).msg_control = ptr::null::<c_void>() as *mut c_void;
            }
        } else {
            let u_control_slice = self
                .allocator
                .new_align_slice_mut(msg_controllen as usize, 8)?;
            let control_slice =
                unsafe { std::slice::from_raw_parts(msg_control as *const u8, msg_controllen) };
            u_control_slice.copy_from_slice(control_slice);
            unsafe { (*msghdr_ptr).msg_control = u_control_slice.as_mut_ptr() as *mut c_void }
        }

        if msg_iov == ptr::null() {
            unsafe {
                (*msghdr_ptr).msg_iov = ptr::null::<libc::iovec>() as *mut libc::iovec;
            }
        } else {
            let u_iov_slice = self.allocator.new_align_slice_mut(
                msg_iovlen * std::mem::size_of::<libc::iovec>(),
                Layout::new::<libc::iovec>().align(),
            )?;
            let iov_slice = unsafe {
                std::slice::from_raw_parts(
                    msg_iov as *const u8,
                    msg_iovlen * std::mem::size_of::<libc::iovec>(),
                )
            };
            u_iov_slice.copy_from_slice(iov_slice);
            unsafe {
                (*msghdr_ptr).msg_iov = u_iov_slice.as_ptr() as *mut libc::iovec;
            }
        }

        unsafe {
            (*msghdr_ptr).msg_namelen = msg_namelen as u32;
            (*msghdr_ptr).msg_iovlen = msg_iovlen;
            (*msghdr_ptr).msg_controllen = msg_controllen;
            (*msghdr_ptr).msg_flags = 0;

            println!(
                "msghdr {:?}, name {:?}, len {}, iov {:?}, len {}, control {:?}, len {}, ",
                msghdr_ptr,
                (*msghdr_ptr).msg_name,
                (*msghdr_ptr).msg_namelen,
                (*msghdr_ptr).msg_iov,
                (*msghdr_ptr).msg_iovlen,
                (*msghdr_ptr).msg_control,
                (*msghdr_ptr).msg_controllen
            );
            if msg_iovlen >= 1 {
                println!(
                    "iovbase {:?}, iovlen {}",
                    (*(*msghdr_ptr).msg_iov).iov_base,
                    (*(*msghdr_ptr).msg_iov).iov_len
                );
            }
        }

        let guard = SQ_LOCK.lock().unwrap();
        let req_id = self.inc_id.fetch_add(1, atomic::Ordering::SeqCst);
        let fixed_fd = self.io_uring_register_files_helper(fd)?;

        let sqe = unsafe { (*self.io_uring).io_uring_get_sqe()? };
        io_uring_prep_sendmsg(
            sqe,
            fixed_fd as i32,
            msghdr_ptr,
            // msg_ptr_test,
            flags as u32,
            req_id,
            IOSQE_FIXED_FILE,
        );
        let submit_num = unsafe { (*self.io_uring).io_uring_submit() };
        // assert!(submit_num >= 1);
        println!("submit num: {}, fd: {}", submit_num, fd);
        drop(guard);

        let bytes_sent = unsafe { (*self.io_uring).io_uring_get_cqe_res(req_id) };
        println!("sendmsg cqe res {}, fd: {}", bytes_sent, fd);
        return Ok(bytes_sent as isize);
    }

    pub fn io_uring_recvmsg(
        &self,
        fd: c_int,
        msg_name: *mut c_void,
        msg_namelen: libc::socklen_t,
        msg_namelen_recv: *mut libc::socklen_t,
        msg_iov: *mut libc::iovec,
        msg_iovlen: size_t,
        msg_control: *mut c_void,
        msg_controllen: size_t,
        msg_controllen_recv: *mut size_t,
        msg_flags: *mut c_int,
        flags: c_int,
        msg_ptr_test: *mut msghdr,
    ) -> Result<isize, ()> {
        println!("io_uring_recvmsg, host_fd: {}, flags: {}, name {:?}, len {}, iov {:?}, len {}, control {:?}, len {}", 
            fd, flags, msg_name, msg_namelen, msg_iov, msg_iovlen, msg_control, msg_controllen);

        // use wrapper C directly
        let bytes_recv = unsafe { do_recvmsg2(fd, msg_ptr_test, flags) };
        println!("recvmsg cqe res {}, fd: {}", bytes_recv, fd);
        return Ok(bytes_recv as isize);

        let u_msghdr = self
            .allocator
            .new_align_slice_mut(
                std::mem::size_of::<msghdr>(),
                Layout::new::<msghdr>().align(),
            )?
            .as_mut_ptr();
        let mut msghdr_ptr = u_msghdr as *mut msghdr;

        if msg_name as *const c_void == ptr::null() {
            unsafe {
                (*msghdr_ptr).msg_name = ptr::null::<c_void>() as *mut c_void;
            }
        } else {
            let u_name_slice = self
                .allocator
                .new_align_slice_mut(msg_namelen as usize, 8)?;
            // let name_slice = unsafe { std::slice::from_raw_parts(msg_name as *const u8, msg_namelen as usize) };
            // u_name_slice.copy_from_slice(name_slice);
            unsafe {
                (*msghdr_ptr).msg_name = u_name_slice.as_ptr() as *mut c_void;
            }
        }

        if msg_control as *const c_void == ptr::null() {
            unsafe {
                (*msghdr_ptr).msg_control = ptr::null::<c_void>() as *mut c_void;
            }
        } else {
            let u_control_slice = self
                .allocator
                .new_align_slice_mut(msg_controllen as usize, 8)?;
            // let control_slice = unsafe { std::slice::from_raw_parts(msg_control as *const u8, msg_controllen) };
            // u_control_slice.copy_from_slice(control_slice);
            unsafe {
                (*msghdr_ptr).msg_control = u_control_slice.as_ptr() as *mut c_void;
            }
        }

        if msg_iov as *const libc::iovec == ptr::null() {
            unsafe {
                (*msghdr_ptr).msg_iov = ptr::null::<libc::iovec>() as *mut libc::iovec;
            }
        } else {
            let u_iov_slice = self.allocator.new_align_slice_mut(
                msg_iovlen * std::mem::size_of::<libc::iovec>(),
                Layout::new::<libc::iovec>().align(),
            )?;
            let iov_slice = unsafe {
                std::slice::from_raw_parts(
                    msg_iov as *const u8,
                    msg_iovlen * std::mem::size_of::<libc::iovec>(),
                )
            };
            u_iov_slice.copy_from_slice(iov_slice);
            unsafe {
                (*msghdr_ptr).msg_iov = u_iov_slice.as_ptr() as *mut libc::iovec;
            }
        }

        unsafe {
            (*msghdr_ptr).msg_namelen = msg_namelen as u32;
            (*msghdr_ptr).msg_iovlen = msg_iovlen;
            (*msghdr_ptr).msg_controllen = msg_controllen;
            (*msghdr_ptr).msg_flags = 0;

            println!(
                "msghdr {:?}, name {:?}, len {}, iov {:?}, len {}, control {:?}, len {}, ",
                msghdr_ptr,
                (*msghdr_ptr).msg_name,
                (*msghdr_ptr).msg_namelen,
                (*msghdr_ptr).msg_iov,
                (*msghdr_ptr).msg_iovlen,
                (*msghdr_ptr).msg_control,
                (*msghdr_ptr).msg_controllen
            );
            if msg_iovlen >= 1 {
                println!(
                    "iovbase {:?}, iovlen {}; iovbase {:?}, iovlen {}",
                    (*(*msghdr_ptr).msg_iov).iov_base,
                    (*(*msghdr_ptr).msg_iov).iov_len,
                    (*msg_iov).iov_base,
                    (*msg_iov).iov_len,
                );
            }
        }

        let guard = SQ_LOCK.lock().unwrap();
        let req_id = self.inc_id.fetch_add(1, atomic::Ordering::SeqCst);
        let fixed_fd = self.io_uring_register_files_helper(fd)?;

        let sqe = unsafe { (*self.io_uring).io_uring_get_sqe()? };
        io_uring_prep_recvmsg(
            sqe,
            fixed_fd as i32,
            msghdr_ptr,
            // msg_ptr_test,
            flags as u32,
            req_id,
            IOSQE_FIXED_FILE,
        );

        let submit_num = unsafe { (*self.io_uring).io_uring_submit() };
        // assert!(submit_num >= 1);
        println!("submit num: {}, fd: {}", submit_num, fd);
        drop(guard);

        let bytes_recv = unsafe { (*self.io_uring).io_uring_get_cqe_res(req_id) };
        println!("recvmsg cqe res {}, fd: {}", bytes_recv, fd);

        unsafe {
            *msg_namelen_recv = (*msghdr_ptr).msg_namelen;
            *msg_controllen_recv = (*msghdr_ptr).msg_controllen;
            *msg_flags = (*msghdr_ptr).msg_flags;

            println!("recvmsg namelen_recv: {}, controllen_recv: {}, flags: {}, name: {:?}, control: {:? }",
                (*msghdr_ptr).msg_namelen, (*msghdr_ptr).msg_controllen, (*msghdr_ptr).msg_flags,
                (*msghdr_ptr).msg_name, (*msghdr_ptr).msg_control);

            if (*msghdr_ptr).msg_name as *const c_void != ptr::null() {
                std::ptr::copy_nonoverlapping(
                    (*msghdr_ptr).msg_name as *const u8,
                    msg_name as *mut u8,
                    msg_namelen as usize,
                );
            }

            if (*msghdr_ptr).msg_control as *const c_void != ptr::null() {
                std::ptr::copy_nonoverlapping(
                    (*msghdr_ptr).msg_control as *const u8,
                    msg_control as *mut u8,
                    msg_controllen,
                );
            }
        }

        return Ok(bytes_recv as isize);
    }
}

unsafe impl Send for IoAgent {}
unsafe impl Sync for IoAgent {}

impl Drop for IoAgent {
    fn drop(&mut self) {
        println!("drop IoAgent");

        unsafe {
            occlum_ocall_io_uring_exit(self.io_uring_addr);
        };
    }
}

lazy_static! {
    pub static ref IO_AGENT: IoAgent = IoAgent::new(IO_URING_SIZE);
}

extern "C" {
    fn occlum_ocall_io_uring_init(ring_size: u32) -> u64;

    fn occlum_ocall_io_uring_exit(io_uring_addr: u64);

    fn occlum_ocall_io_uring_register_files(
        io_uring_addr: u64,
        fds: *const i32,
        fds_len: u32,
    ) -> i32;

    fn occlum_ocall_io_uring_update_file(io_uring_addr: u64, fd: i32, offset: u32) -> i32;

    fn init_io_uring2();
    fn c_clear_register_files2();
    fn do_sendmsg2(fd: i32, msg_ptr: *mut msghdr, flags: i32) -> i32;
    fn do_recvmsg2(fd: i32, msg_ptr: *mut msghdr, flags: i32) -> i32;

}
