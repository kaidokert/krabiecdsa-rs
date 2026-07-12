// Linker symbols: their *addresses* carry the values. `&sym as usize`
// is the correct read — never dereference these.
unsafe extern "C" {
    static _stack_start: u32;
    static _sheap: u32;
}

const SAFE_ZONE_BYTES: usize = 256;

#[inline(always)]
pub fn paint_stack() {
    paint_stack_inner::<SAFE_ZONE_BYTES>();
}

#[inline(always)]
pub fn check_stack_high_water_mark() -> usize {
    check_stack_high_water_mark_inner::<SAFE_ZONE_BYTES>()
}

pub fn paint_stack_inner<const SAFE: usize>() {
    unsafe {
        let stack_start = &_stack_start as *const u32 as *mut u8;
        // Paint floor: first byte past .bss/.data, so statics can never
        // be overwritten no matter how large they grow.
        let paint_start = &_sheap as *const u32 as *mut u8;

        // Read current SP and stop the paint a margin below it, so we never
        // overwrite the live stack frame.
        let mut sp: usize;
        core::arch::asm!("mv {}, sp", out(reg) sp, options(nomem, nostack));
        let live_limit = (sp as *mut u8).offset(-(SAFE as isize));

        let paint_end = if (live_limit as usize) < (paint_start as usize) {
            paint_start
        } else {
            live_limit
        };

        let bytes_to_write = (paint_end as usize).saturating_sub(paint_start as usize);
        if bytes_to_write > 0 {
            core::ptr::write_bytes(paint_start, 0xAA, bytes_to_write);
        }
    }
}

pub fn check_stack_high_water_mark_inner<const SAFE: usize>() -> usize {
    unsafe {
        let stack_start = &_stack_start as *const u32 as *mut u8;
        let paint_start = &_sheap as *const u32 as *mut u8;

        let mut current = paint_start;
        while current < stack_start && *current == 0xAA {
            current = current.offset(1);
        }

        stack_start.offset_from(current) as usize
    }
}
