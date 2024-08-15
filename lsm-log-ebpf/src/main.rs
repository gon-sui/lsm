#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    helpers::{bpf_probe_read_user, bpf_get_current_pid_tgid},
};
use aya_log_ebpf::info;
use lsm_log_common::ConnectEvent;

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<ConnectEvent> = PerfEventArray::with_max_entries(1024, 0);

#[repr(C)]
struct sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[tracepoint(name = "sys_enter_connect" , category = "syscall")]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_connect(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_sys_enter_connect(ctx: &TracePointContext) -> Result<u32, u32> {
    let args = ctx.read_at::<*const sockaddr_in>(16).map_err(|_| 1u32)?;
    let sockaddr = bpf_probe_read_user(args).map_err(|_| 2u32)?;

    if sockaddr.sin_family == 2 { // AF_INET
        let event = ConnectEvent {
            pid: (bpf_get_current_pid_tgid() >> 32) as u32,
            ip: sockaddr.sin_addr,
            port: u16::from_be(sockaddr.sin_port),
        };

        EVENTS.output(ctx, &event, 0);
        info!(ctx, "Connect: PID: {}, IP: {:x}, Port: {}", event.pid, event.ip, event.port);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
