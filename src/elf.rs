//! Minimal ELF64 (little-endian) surgery.
//!
//! Injects a read-only data segment by repurposing an existing `PT_NOTE`
//! program header into a `PT_LOAD` that points to bytes appended at the end of
//! the file (the classic Silvio Cesare technique). The program header table is
//! not shifted, so every existing offset of the input binary is preserved.

use std::error::Error;
use std::fmt;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const PF_R: u32 = 4;

const PAGE: u64 = 0x1000;

// ELF64 header field offsets.
const E_PHOFF: usize = 0x20;
const E_PHENTSIZE: usize = 0x36;
const E_PHNUM: usize = 0x38;

// ELF64 program header field offsets, relative to the entry start.
const P_TYPE: usize = 0x00;
const P_FLAGS: usize = 0x04;
const P_OFFSET: usize = 0x08;
const P_VADDR: usize = 0x10;
const P_PADDR: usize = 0x18;
const P_FILESZ: usize = 0x20;
const P_MEMSZ: usize = 0x28;
const P_ALIGN: usize = 0x30;
const PHDR64_SIZE: usize = 0x38;

#[derive(Debug)]
pub struct InjectError(String);

impl fmt::Display for InjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "elf injection: {}", self.0)
    }
}

impl Error for InjectError {}

fn err<T>(msg: impl Into<String>) -> Result<T, InjectError> {
    Err(InjectError(msg.into()))
}

/// Modified binary and the location of the injected payload.
pub struct Injection {
    pub data: Vec<u8>,
    pub vaddr: u64,
    pub offset: u64,
    pub len: u64,
}

/// Injects `payload` as a read-only `PT_LOAD` segment by repurposing a
/// `PT_NOTE` program header. Returns the modified binary and the payload
/// location.
pub fn inject_note_as_load(mut data: Vec<u8>, payload: &[u8]) -> Result<Injection, InjectError> {
    validate_header(&data)?;

    let phoff = read_u64(&data, E_PHOFF) as usize;
    let phentsize = read_u16(&data, E_PHENTSIZE) as usize;
    let phnum = read_u16(&data, E_PHNUM) as usize;

    if phentsize < PHDR64_SIZE {
        return err("program header entry smaller than ELF64");
    }

    // Locate the first PT_NOTE to repurpose and the top of the loaded image.
    let mut note_ph: Option<usize> = None;
    let mut max_vaddr_end: u64 = 0;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if ph + PHDR64_SIZE > data.len() {
            return err("program header table out of bounds");
        }
        match read_u32(&data, ph + P_TYPE) {
            PT_NOTE if note_ph.is_none() => note_ph = Some(ph),
            PT_LOAD => {
                let end = read_u64(&data, ph + P_VADDR) + read_u64(&data, ph + P_MEMSZ);
                max_vaddr_end = max_vaddr_end.max(end);
            }
            _ => {}
        }
    }

    let ph = match note_ph {
        Some(ph) => ph,
        None => return err("no PT_NOTE segment to repurpose in the input binary"),
    };

    // Append the payload at a page-aligned file offset.
    let offset = align_up(data.len() as u64, PAGE);
    data.resize(offset as usize, 0);
    data.extend_from_slice(payload);

    // Place the segment on a page-aligned address one page above the image top.
    // Both offset and vaddr are multiples of PAGE, so the PT_LOAD congruence
    // (p_vaddr == p_offset mod p_align) holds by construction.
    let vaddr = align_up(max_vaddr_end, PAGE) + PAGE;
    let len = payload.len() as u64;

    // Rewrite the PT_NOTE entry as a PT_LOAD pointing at the payload.
    write_u32(&mut data, ph + P_TYPE, PT_LOAD);
    write_u32(&mut data, ph + P_FLAGS, PF_R);
    write_u64(&mut data, ph + P_OFFSET, offset);
    write_u64(&mut data, ph + P_VADDR, vaddr);
    write_u64(&mut data, ph + P_PADDR, vaddr);
    write_u64(&mut data, ph + P_FILESZ, len);
    write_u64(&mut data, ph + P_MEMSZ, len);
    write_u64(&mut data, ph + P_ALIGN, PAGE);

    Ok(Injection {
        data,
        vaddr,
        offset,
        len,
    })
}

fn validate_header(data: &[u8]) -> Result<(), InjectError> {
    if data.len() < 64 {
        return err("file smaller than ELF64 header");
    }
    if data[0..4] != ELF_MAGIC {
        return err("not an ELF file");
    }
    if data[4] != ELFCLASS64 {
        return err("only ELF64 is supported");
    }
    if data[5] != ELFDATA2LSB {
        return err("only little-endian ELF is supported");
    }
    Ok(())
}

fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

fn read_u16(d: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([d[off], d[off + 1]])
}

fn read_u32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

fn read_u64(d: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[off..off + 8]);
    u64::from_le_bytes(b)
}

fn write_u32(d: &mut [u8], off: usize, v: u32) {
    d[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_u64(d: &mut [u8], off: usize, v: u64) {
    d[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
