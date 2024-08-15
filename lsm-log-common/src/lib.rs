#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ConnectEvent {
    pub pid: u32,
    pub ip: u32,
    pub port: u16,
}
