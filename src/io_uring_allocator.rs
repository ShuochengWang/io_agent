use super::*;
use std::alloc::{alloc, Layout};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub struct IoUringAllocator {
    buf_ptr: *mut u8,
    buf_size: usize,
    buf_pos: AtomicUsize,
}

impl IoUringAllocator {
    pub fn empty_alloc() -> IoUringAllocator {
        Self {
            buf_ptr: std::ptr::null_mut(),
            buf_size: 0,
            buf_pos: AtomicUsize::new(0),
        }
    }
    
    pub fn new(buf_size: usize) -> Result<Self, ()> {
        let layout = unsafe { Layout::from_size_align_unchecked(buf_size, 1) };
        let buf_ptr = unsafe { alloc(layout) };
        let buf_pos = AtomicUsize::new(0);
        println!("IoUringAllocator init. buf_ptr: {:?}, buf_size: {}", buf_ptr, buf_size);
        Ok(Self {
            buf_ptr,
            buf_size,
            buf_pos,
        })
    }

    pub fn new_align_slice_mut(&self, new_slice_len: usize, align: usize) -> Result<&mut [u8], ()> {
        // align must not be zero; align must be a power of 2
        assert!((align != 0) && (align & (align - 1)) == 0);

        let new_slice_ptr = {
            let mut pos = self
                .buf_pos
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |old_pos| {
                    let mut new_pos = old_pos + new_slice_len;

                    if old_pos % align != 0 {
                        new_pos += align - old_pos % align;
                    }

                    if new_pos <= self.buf_size {
                        Some(new_pos)
                    } else {
                        None
                    }
                });

            if let Ok(p) = pos {
                let mut mp = p;
                if mp % align != 0 {
                    mp += align - mp % align;
                }
                unsafe { self.buf_ptr.add(mp) }
            } else {
                println!("new_align_slice_mut error.");
                unsafe { self.buf_ptr.add(0) }
            }
        };

        assert!(new_slice_ptr as usize % align == 0);
        let new_slice = unsafe { std::slice::from_raw_parts_mut(new_slice_ptr, new_slice_len) };
        Ok(new_slice)
    }
}