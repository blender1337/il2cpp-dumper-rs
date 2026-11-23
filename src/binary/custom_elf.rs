#![allow(dead_code)]

use std::collections::HashMap;
use goblin::elf::Elf;

use crate::metadata::adaptive::{is_valid_name, AdaptiveType};
use super::BinaryImage;

#[derive(Debug, Clone, Default)]
pub struct AdaptiveRegContext {
    pub code_reg_va: Option<u64>,
    pub meta_reg_va: Option<u64>,
    pub matched_symbol: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AdaptiveFieldTypeInfo {
    pub type_name: String,
    pub attrs: u16,
    pub is_static: bool,
    pub resolved: bool,
}

pub fn decode_adrp(pc: u64, insn: u32) -> u64 {
    let immlo = ((insn >> 29) & 0x3) as i64;
    let immhi = ((insn >> 5) & 0x7_FFFF) as i64;
    let mut imm = (immhi << 2) | immlo;
    if (imm & (1 << 20)) != 0 {
        imm -= 1 << 21;
    }
    ((pc & !0xFFFu64) as i64).wrapping_add(imm << 12) as u64
}

fn is_data_proc_write(insn: u32) -> bool {
    (insn & 0x1F00_0000) == 0x0A00_0000
        || (insn & 0x1F00_0000) == 0x1000_0000
        || (insn & 0x3B00_0000) == 0x3900_0000
}

pub fn find_registration_context(
    bin: &BinaryImage,
    custom_sym: Option<&str>,
) -> AdaptiveRegContext {
    let mut ctx = trace_dynsym_arm64(bin, custom_sym);
    if ctx.code_reg_va.is_none() {
        let init_ctx = trace_init_array(bin);
        if init_ctx.code_reg_va.is_some() {
            ctx.code_reg_va = init_ctx.code_reg_va;
            if ctx.meta_reg_va.is_none() {
                ctx.meta_reg_va = init_ctx.meta_reg_va;
            }
            if ctx.matched_symbol.is_none() {
                ctx.matched_symbol = init_ctx.matched_symbol;
            }
        }
    }
    if ctx.code_reg_va.is_none() {
        ctx.code_reg_va = scan_code_registration(bin);
    }
    ctx
}

fn trace_init_array(bin: &BinaryImage) -> AdaptiveRegContext {
    let mut ctx = AdaptiveRegContext::default();
    let (init_va, init_sz) = if let Some(init_sec) = bin.sections.iter().find(|s| s.name == ".init_array") {
        (init_sec.va_start, init_sec.file_size)
    } else if let Ok(elf) = Elf::parse(&bin.bytes) {
        let dyn_info = super::elf::extract_dynamic_info(&elf);
        match dyn_info.init_array_va {
            Some(va) if dyn_info.init_array_sz > 0 => (va, dyn_info.init_array_sz as usize),
            _ => return ctx,
        }
    } else {
        return ctx;
    };

    let ptr_sz = bin.ptr_size() as u64;
    let count = init_sz / ptr_sz as usize;
    for idx in 0..count.min(256) {
        let Some(fn_va) = bin.read_ptr(init_va + idx as u64 * ptr_sz) else {
            continue;
        };
        if !bin.is_valid_va(fn_va) {
            continue;
        }
        if bin.arch == "arm64" && bin.is_64bit {
            if let Some((cr, mr)) = trace_arm64_init_fn(bin, fn_va, 0) {
                ctx.code_reg_va = Some(cr);
                ctx.meta_reg_va = mr;
                ctx.matched_symbol = Some(".init_array (arm64)".to_string());
                return ctx;
            }
        } else if bin.arch == "x86_64" && bin.is_64bit {
            if let Some((cr, mr)) = trace_x86_64_init_fn(bin, fn_va) {
                ctx.code_reg_va = Some(cr);
                ctx.meta_reg_va = mr;
                ctx.matched_symbol = Some(".init_array (x86_64)".to_string());
                return ctx;
            }
        }
    }
    ctx
}

fn validate_cr_candidate(bin: &BinaryImage, code_reg_va: u64) -> bool {
    if !bin.is_valid_va(code_reg_va) {
        return false;
    }
    let ptr_sz = bin.ptr_size() as u64;
    for off in (64..=200u64).step_by(ptr_sz as usize) {
        let cnt = bin.read_ptr(code_reg_va + off).unwrap_or(0);
        if (1..=500).contains(&cnt) {
            let arr = bin.read_ptr(code_reg_va + off + ptr_sz).unwrap_or(0);
            if is_valid_cgm_array(bin, arr, cnt) {
                return true;
            }
        }
    }
    false
}

fn trace_arm64_init_fn(
    bin: &BinaryImage,
    fn_va: u64,
    depth: usize,
) -> Option<(u64, Option<u64>)> {
    let mut regs: HashMap<u32, u64> = HashMap::new();
    for i in 0..64u64 {
        let pc = fn_va + i * 4;
        let insn = bin.read_u32(pc)?;
        let rd = insn & 0x1F;
        let rn = (insn >> 5) & 0x1F;
        let op = insn >> 26;

        if (insn & 0x9F00_0000) == 0x9000_0000 {
            regs.insert(rd, decode_adrp(pc, insn));
        } else if (insn & 0xFF80_0000) == 0x9100_0000 {
            if let Some(&base) = regs.get(&rn) {
                let mut imm12 = ((insn >> 10) & 0xFFF) as u64;
                if ((insn >> 22) & 3) != 0 {
                    imm12 <<= 12;
                }
                regs.insert(rd, base.wrapping_add(imm12));
            } else {
                regs.remove(&rd);
            }
        } else if op == 0x05 || op == 0x25 {
            if let (Some(&x0), Some(&x1)) = (regs.get(&0), regs.get(&1)) {
                if validate_cr_candidate(bin, x0) && bin.is_valid_va(x1) {
                    return Some((x0, Some(x1)));
                }
            }
            if depth == 0 && i < 6 {
                let mut imm26 = (insn & 0x03FF_FFFF) as i32;
                if (imm26 & (1 << 25)) != 0 {
                    imm26 -= 1 << 26;
                }
                let dest = (pc as i64).wrapping_add((imm26 as i64) << 2) as u64;
                if bin.is_valid_va(dest) {
                    if let Some(found) = trace_arm64_init_fn(bin, dest, 1) {
                        return Some(found);
                    }
                }
            }
        } else if insn == 0xD65F_03C0 {
            break;
        } else if is_data_proc_write(insn) && rd != 31 {
            regs.remove(&rd);
        }
    }
    None
}

fn trace_x86_64_init_fn(bin: &BinaryImage, fn_va: u64) -> Option<(u64, Option<u64>)> {
    let bytes = bin.read_bytes(fn_va, 96)?;
    let mut arg1 = None;
    let mut arg2 = None;
    let mut i = 0usize;
    while i + 7 <= bytes.len() {
        if bytes[i] == 0x48 && bytes[i + 1] == 0x8D {
            let modrm = bytes[i + 2];
            let disp = i32::from_le_bytes([bytes[i + 3], bytes[i + 4], bytes[i + 5], bytes[i + 6]]);
            let next_ip = fn_va + (i + 7) as u64;
            let target = (next_ip as i64).wrapping_add(disp as i64) as u64;
            // LEA RCX (0x0D) / LEA RDI (0x3D) -> arg1; LEA RDX (0x15) / LEA RSI (0x35) -> arg2
            if modrm == 0x0D || modrm == 0x3D {
                arg1 = Some(target);
            } else if modrm == 0x15 || modrm == 0x35 {
                arg2 = Some(target);
            }
            i += 7;
            continue;
        }
        if bytes[i] == 0xC3 {
            break;
        }
        i += 1;
    }
    if let (Some(a1), Some(a2)) = (arg1, arg2) {
        if validate_cr_candidate(bin, a1) && bin.is_valid_va(a2) {
            return Some((a1, Some(a2)));
        }
    }
    None
}

/// Locate an AArch64 PLT stub targeting `got_va` via `ADRP X16` + `LDR X17, [X16, #off]`.
pub fn find_arm64_plt_stub_for_got(bin: &BinaryImage, got_va: u64) -> Option<u64> {
    if bin.arch != "arm64" || !bin.is_64bit || got_va == 0 {
        return None;
    }
    for seg in &bin.sections {
        if !seg.is_exec || seg.file_size < 8 {
            continue;
        }
        let mut i = 0usize;
        while i + 8 <= seg.file_size {
            let off = seg.file_offset + i;
            let Some(insn) = read_u32_raw(&bin.bytes, off) else {
                break;
            };
            if (insn & 0x9F00_001F) == 0x9000_0010 {
                let pc = seg.va_start + i as u64;
                let page = decode_adrp(pc, insn);
                for delta in [4usize, 8usize] {
                    if let Some(insn2) = read_u32_raw(&bin.bytes, off + delta) {
                        if (insn2 & 0xFFC0_03FF) == 0xF940_0211 {
                            let imm12 = ((insn2 >> 10) & 0xFFF) as u64 * 8;
                            if page.wrapping_add(imm12) == got_va {
                                if pc >= seg.va_start + 4 && bin.read_u32(pc - 4) == Some(0xD503_245F) {
                                    return Some(pc - 4);
                                }
                                return Some(pc);
                            }
                        }
                    }
                }
            }
            i += 4;
        }
    }
    None
}

fn find_branch_caller(bin: &BinaryImage, target_va: u64) -> Option<u64> {
    for seg in &bin.sections {
        if !seg.is_exec {
            continue;
        }
        let mut i = 0usize;
        while i + 4 <= seg.file_size {
            let off = seg.file_offset + i;
            let Some(insn) = read_u32_raw(&bin.bytes, off) else {
                break;
            };
            let op = insn >> 26;
            if op == 0x05 || op == 0x25 {
                let mut imm26 = (insn & 0x03FF_FFFF) as i32;
                if (imm26 & (1 << 25)) != 0 {
                    imm26 -= 1 << 26;
                }
                let pc = seg.va_start + i as u64;
                let dest = (pc as i64).wrapping_add((imm26 as i64) << 2) as u64;
                if dest == target_va {
                    return Some(pc);
                }
            }
            i += 4;
        }
    }
    None
}

fn trace_dynsym_arm64(bin: &BinaryImage, custom_sym: Option<&str>) -> AdaptiveRegContext {
    let mut ctx = AdaptiveRegContext::default();
    if !bin.is_64bit {
        return ctx;
    }
    let Ok(elf) = Elf::parse(&bin.bytes) else {
        return ctx;
    };

    let mut dynsym_sec = None;
    let mut dynstr_sec = None;
    let mut relaplt_sec = None;
    let mut plt_sec = None;

    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            match name {
                ".dynsym" => dynsym_sec = Some(sh),
                ".dynstr" => dynstr_sec = Some(sh),
                ".rela.plt" => relaplt_sec = Some(sh),
                ".plt" => plt_sec = Some(sh),
                _ => {}
            }
        }
    }

    let dyn_info = super::elf::extract_dynamic_info(&elf);
    let (dynsym_off, dynsym_cnt) = match dynsym_sec {
        Some(s) => (s.sh_offset as usize, (s.sh_size / 24) as usize),
        None => match (
            dyn_info.symtab_va.and_then(|va| bin.va_to_offset(va)),
            super::elf::estimate_dynsym_count(&dyn_info, |va| bin.va_to_offset(va), &bin.bytes, bin.is_64bit),
        ) {
            (Some(off), Some(cnt)) => (off, cnt),
            _ => return ctx,
        },
    };
    let (dynstr_off, dynstr_sz) = match dynstr_sec {
        Some(s) => (s.sh_offset as usize, s.sh_size as usize),
        None => match dyn_info.strtab_va.and_then(|va| bin.va_to_offset(va)) {
            Some(off) if dyn_info.strsz > 0 => (off, dyn_info.strsz as usize),
            _ => return ctx,
        },
    };
    let (relaplt_off, rela_count) = match relaplt_sec {
        Some(s) => (s.sh_offset as usize, (s.sh_size / 24) as usize),
        None => match dyn_info.jmprel_va.and_then(|va| bin.va_to_offset(va)) {
            Some(off) if dyn_info.pltrelsz >= 24 => (off, (dyn_info.pltrelsz / 24) as usize),
            _ => return ctx,
        },
    };

    let mut candidates: Vec<&str> = Vec::new();
    if let Some(cs) = custom_sym {
        if !cs.is_empty() {
            candidates.push(cs);
        }
    }
    candidates.push("_Z28il2cpp_codegen_register_moba");
    candidates.push("il2cpp_codegen_register_moba");
    candidates.push("il2cpp_codegen_register");

    let mut target_sym_idx: Option<u32> = None;
    'outer: for pat in candidates {
        for idx in 0..dynsym_cnt {
            let off = dynsym_off + idx * 24;
            if let Some(st_name) = read_u32_raw(&bin.bytes, off) {
                let s_off = st_name as usize;
                if s_off < dynstr_sz {
                    let abs = dynstr_off + s_off;
                    let end = bin.bytes.len().min(dynstr_off + dynstr_sz);
                    if abs < end {
                        let tail = &bin.bytes[abs..end];
                        let nul = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
                        if let Ok(sym_name) = std::str::from_utf8(&tail[..nul]) {
                            if sym_name.contains(pat) {
                                target_sym_idx = Some(idx as u32);
                                ctx.matched_symbol = Some(sym_name.to_string());
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }
    }

    let Some(sym_idx) = target_sym_idx else {
        return ctx;
    };

    let mut matched_plt: Option<(usize, u64)> = None;
    for j in 0..rela_count {
        let off = relaplt_off + j * 24;
        if let Some(r_info) = read_u64_raw(&bin.bytes, off + 8) {
            if (r_info >> 32) as u32 == sym_idx {
                let r_offset = read_u64_raw(&bin.bytes, off).unwrap_or(0);
                matched_plt = Some((j, r_offset));
                break;
            }
        }
    }
    let Some((pidx, got_slot_va)) = matched_plt else {
        return ctx;
    };

    let mut caller_pc = None;
    if let Some(plt) = plt_sec {
        let plt_entry_size = if rela_count > 0 && plt.sh_size > 32 {
            let derived = ((plt.sh_size - 32) / rela_count as u64) as usize;
            if (16..=32).contains(&derived) {
                derived
            } else {
                16
            }
        } else {
            16
        };
        let plt_stub_va = plt.sh_addr + 32 + (pidx * plt_entry_size) as u64;
        caller_pc = find_branch_caller(bin, plt_stub_va);
    }
    if caller_pc.is_none() {
        if let Some(stub_va) = find_arm64_plt_stub_for_got(bin, got_slot_va) {
            caller_pc = find_branch_caller(bin, stub_va);
        }
    }

    let Some(cpc) = caller_pc else {
        return ctx;
    };

    let mut regs: HashMap<u32, u64> = HashMap::new();
    for k in (1..=20u64).rev() {
        let Some(insn_va) = cpc.checked_sub(k * 4) else {
            continue;
        };
        let Some(insn) = bin.read_u32(insn_va) else {
            continue;
        };
        let rd = insn & 0x1F;
        let rn = (insn >> 5) & 0x1F;
        if (insn & 0x9F00_0000) == 0x9000_0000 {
            regs.insert(rd, decode_adrp(insn_va, insn));
        } else if (insn & 0xFF80_0000) == 0x9100_0000 {
            if let Some(&base) = regs.get(&rn) {
                let mut imm12 = ((insn >> 10) & 0xFFF) as u64;
                if ((insn >> 22) & 3) != 0 {
                    imm12 <<= 12;
                }
                regs.insert(rd, base.wrapping_add(imm12));
            } else {
                regs.remove(&rd);
            }
        } else if (insn & 0xFFE0_FFE0) == 0xAA00_03E0 {
            let xm = (insn >> 16) & 0x1F;
            if let Some(&val) = regs.get(&xm) {
                regs.insert(rd, val);
            } else {
                regs.remove(&rd);
            }
        } else if is_data_proc_write(insn) && rd != 31 {
            regs.remove(&rd);
        }
    }

    ctx.code_reg_va = regs.get(&0).copied();
    ctx.meta_reg_va = regs.get(&1).copied();
    ctx
}

fn read_u32_raw(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64_raw(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off + 8)?;
    let arr: [u8; 8] = s.try_into().ok()?;
    Some(u64::from_le_bytes(arr))
}

fn is_valid_cgm_array(bin: &BinaryImage, cgm_array_va: u64, mod_count: u64) -> bool {
    if cgm_array_va == 0 || mod_count == 0 || mod_count > 1000 {
        return false;
    }
    let Some(first_mod) = bin.read_ptr(cgm_array_va) else {
        return false;
    };
    let Some(name_ptr) = bin.read_ptr(first_mod) else {
        return false;
    };
    let Some(mod_name) = bin.read_cstr(name_ptr) else {
        return false;
    };
    mod_name.contains(".dll") || mod_name.contains("Assembly") || mod_name.contains("mscorlib")
}

pub fn scan_code_registration(bin: &BinaryImage) -> Option<u64> {
    let ptr_sz = bin.ptr_size() as u64;
    for s in &bin.sections {
        if s.is_exec || s.file_size < 136 {
            continue;
        }
        let mut off = 0usize;
        while off + 136 <= s.file_size {
            let v = s.va_start + off as u64;
            let mod_cnt = bin.read_ptr(v + 120).unwrap_or(0);
            if (1..=200).contains(&mod_cnt) {
                let cgm_arr = bin.read_ptr(v + 128).unwrap_or(0);
                if is_valid_cgm_array(bin, cgm_arr, mod_cnt) {
                    return Some(v);
                }
            }
            off += ptr_sz as usize;
        }
    }
    for s in &bin.sections {
        if s.is_exec || s.file_size < 136 {
            continue;
        }
        let mut off = 0usize;
        while off + 136 <= s.file_size {
            let v = s.va_start + off as u64;
            for delta in (64..=320u64).step_by(8) {
                let mod_cnt = bin.read_ptr(v + delta).unwrap_or(0);
                if !(1..=200).contains(&mod_cnt) {
                    continue;
                }
                let cgm_arr = bin.read_ptr(v + delta + 8).unwrap_or(0);
                if is_valid_cgm_array(bin, cgm_arr, mod_cnt) {
                    return Some(v);
                }
            }
            off += ptr_sz as usize;
        }
    }
    None
}

pub fn extract_method_rvas(bin: &BinaryImage, code_reg_va: u64) -> Vec<u64> {
    let mut all_rvas = Vec::new();
    let ptr_sz = bin.ptr_size() as u64;
    let mut mod_count = bin.read_ptr(code_reg_va + 120).unwrap_or(0);
    let mut cgm_array_va = bin.read_ptr(code_reg_va + 128).unwrap_or(0);

    if !is_valid_cgm_array(bin, cgm_array_va, mod_count) {
        let mut found = false;
        for off in (64..=320u64).step_by(8) {
            let cnt = bin.read_ptr(code_reg_va + off).unwrap_or(0);
            if cnt > 0 && cnt < 1000 {
                let arr = bin.read_ptr(code_reg_va + off + 8).unwrap_or(0);
                if is_valid_cgm_array(bin, arr, cnt) {
                    mod_count = cnt;
                    cgm_array_va = arr;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return all_rvas;
        }
    }

    let table_looks_valid = |tbl: u64, cnt: u32| -> bool {
        if tbl == 0 || cnt == 0 || cnt > 2_000_000 {
            return false;
        }
        let Some(foff) = bin.va_to_offset(tbl) else {
            return false;
        };
        if foff + (cnt as usize) * ptr_sz as usize > bin.bytes.len() {
            return false;
        }
        let sample = cnt.min(8);
        let mut good = 0u32;
        for k in 0..sample {
            let p = bin.read_ptr(tbl + k as u64 * ptr_sz).unwrap_or(0);
            if p == 0 || bin.is_valid_va(p) {
                good += 1;
            }
        }
        good >= sample * 3 / 4
    };

    for m in 0..mod_count {
        let Some(cgm_va) = bin.read_ptr(cgm_array_va + m * ptr_sz) else {
            continue;
        };
        if cgm_va == 0 {
            continue;
        }
        let mut mp_count = bin.read_u32(cgm_va + 8).unwrap_or(0);
        let mut mp_table = bin.read_ptr(cgm_va + 16).unwrap_or(0);
        if !table_looks_valid(mp_table, mp_count) {
            let mut found = false;
            for off in (8..=64u64).step_by(4) {
                let cnt = bin.read_u32(cgm_va + off).unwrap_or(0);
                let tbl = bin.read_ptr(cgm_va + off + 8).unwrap_or(0);
                if table_looks_valid(tbl, cnt) {
                    mp_count = cnt;
                    mp_table = tbl;
                    found = true;
                    break;
                }
            }
            if !found {
                continue;
            }
        }
        for i in 0..mp_count {
            let va = bin.read_ptr(mp_table + i as u64 * ptr_sz).unwrap_or(0);
            all_rvas.push(va);
        }
    }
    all_rvas
}

fn is_valid_field_offsets_table(bin: &BinaryImage, table_va: u64, types: &[AdaptiveType]) -> bool {
    if table_va == 0 {
        return false;
    }
    let ptr_sz = bin.ptr_size() as u64;
    let mut hits = 0;
    for t in types.iter().take(500) {
        if t.field_count == 0 {
            continue;
        }
        if let Some(arr_va) = bin.read_ptr(table_va + t.index as u64 * ptr_sz) {
            if let Some(off) = bin.va_to_offset(arr_va) {
                if off + t.field_count as usize * 2 <= bin.bytes.len() {
                    hits += 1;
                    if hits >= 5 {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub fn scan_metadata_registration(bin: &BinaryImage, types: &[AdaptiveType]) -> Option<u64> {
    let ptr_sz = bin.ptr_size() as u64;
    for s in &bin.sections {
        if s.is_exec || s.file_size < 96 {
            continue;
        }
        let mut off = 0usize;
        while off + 96 <= s.file_size {
            let v = s.va_start + off as u64;
            let fo_table = bin.read_ptr(v + 88).unwrap_or(0);
            if is_valid_field_offsets_table(bin, fo_table, types) {
                return Some(v);
            }
            off += ptr_sz as usize;
        }
    }
    for s in &bin.sections {
        if s.is_exec || s.file_size < 96 {
            continue;
        }
        let mut off = 0usize;
        while off + 96 <= s.file_size {
            let v = s.va_start + off as u64;
            for delta in (32..=128u64).step_by(8) {
                let cnt = bin.read_u32(v + delta).unwrap_or(0);
                if !(64..=2_000_000).contains(&cnt) {
                    continue;
                }
                let arr = bin.read_ptr(v + delta + 8).unwrap_or(0);
                if detect_type_stride(bin, cnt, arr, types).is_some() {
                    return Some(v);
                }
            }
            off += ptr_sz as usize;
        }
    }
    None
}

pub fn extract_field_offsets(
    bin: &BinaryImage,
    types: &[AdaptiveType],
    meta_reg_va: u64,
) -> HashMap<usize, Vec<u32>> {
    let mut res = HashMap::new();
    let ptr_sz = bin.ptr_size() as u64;
    let mut fo_table = bin.read_ptr(meta_reg_va + 88).unwrap_or(0);
    if !is_valid_field_offsets_table(bin, fo_table, types) {
        let mut found = false;
        for off in (48..=256u64).step_by(8) {
            let cand = bin.read_ptr(meta_reg_va + off).unwrap_or(0);
            if is_valid_field_offsets_table(bin, cand, types) {
                fo_table = cand;
                found = true;
                break;
            }
        }
        if !found {
            return res;
        }
    }

    for t in types {
        if t.field_count == 0 {
            continue;
        }
        let Some(arr_va) = bin.read_ptr(fo_table + t.index as u64 * ptr_sz) else {
            continue;
        };
        let Some(arr_off) = bin.va_to_offset(arr_va) else {
            continue;
        };
        let n = t.field_count as usize;
        if arr_off + n * 2 > bin.bytes.len() {
            continue;
        }
        let mut off16 = Vec::with_capacity(n);
        for f in 0..n {
            let b = &bin.bytes[arr_off + f * 2..arr_off + f * 2 + 2];
            off16.push(u16::from_le_bytes([b[0], b[1]]) as u32);
        }
        if n > 1 && arr_off + n * 4 <= bin.bytes.len() {
            let mut off32 = Vec::with_capacity(n);
            let mut plausible32 = true;
            for f in 0..n {
                let val = read_u32_raw(&bin.bytes, arr_off + f * 4).unwrap_or(u32::MAX);
                if val > 0x0080_0000 {
                    plausible32 = false;
                    break;
                }
                off32.push(val);
            }
            if plausible32 {
                let monotonic = |v: &[u32]| -> f64 {
                    let ok = v.windows(2).filter(|w| w[1] >= w[0]).count();
                    ok as f64 / (v.len() - 1) as f64
                };
                let m16 = monotonic(&off16);
                let m32 = monotonic(&off32);
                if m32 >= 0.8 && m32 > m16 + 0.15 {
                    res.insert(t.index, off32);
                    continue;
                }
            }
        }
        res.insert(t.index, off16);
    }
    res
}

fn score_types_array(
    bin: &BinaryImage,
    count: u32,
    array_va: u64,
    types: &[AdaptiveType],
    stride: u32,
) -> i32 {
    if array_va == 0 || !(64..=2_000_000).contains(&count) || stride < 16 {
        return -1;
    }
    let window = count.min(8);
    let mut plausible = 0i32;
    for w in 0..4u32 {
        let start = (count - window) * w / 4;
        for k in 0..window {
            let idx = start + k;
            let type_va = array_va + idx as u64 * stride as u64;
            let Some(type_off) = bin.va_to_offset(type_va) else {
                return -1;
            };
            if type_off + stride as usize > bin.bytes.len() {
                return -1;
            }
            let Some(bits) = read_u32_raw(&bin.bytes, type_off + 8) else {
                return -1;
            };
            let kind = ((bits >> 16) & 0xFF) as u8;
            if !(1..=30).contains(&kind) {
                continue;
            }
            if kind == 17 || kind == 18 {
                let handle = bin.read_ptr(type_va).unwrap_or(u64::MAX);
                if ((handle & 0x00FF_FFFF) as usize) < types.len() {
                    plausible += 1;
                }
            } else if kind == 15 || kind == 29 || kind == 21 {
                let inner = bin.read_ptr(type_va).unwrap_or(0);
                if inner != 0 && bin.is_valid_va(inner) {
                    plausible += 1;
                }
            } else {
                plausible += 1;
            }
        }
    }
    plausible
}

fn detect_type_stride(
    bin: &BinaryImage,
    count: u32,
    array_va: u64,
    types: &[AdaptiveType],
) -> Option<u32> {
    let sample = count.min(32) as i32;
    let thresh = (sample * 3 + 3) / 4;
    let mut best = None;
    let mut best_score = -1;
    for stride in [16u32, 24, 32] {
        let sc = score_types_array(bin, count, array_va, types, stride);
        if sc >= thresh && sc > best_score {
            best_score = sc;
            best = Some(stride);
        }
    }
    best
}

pub fn find_types_array(
    bin: &BinaryImage,
    meta_reg_va: u64,
    types: &[AdaptiveType],
) -> Option<(u32, u64, u32)> {
    let c0 = bin.read_u32(meta_reg_va + 48).unwrap_or(0);
    let a0 = bin.read_ptr(meta_reg_va + 56).unwrap_or(0);
    if let Some(st) = detect_type_stride(bin, c0, a0, types) {
        return Some((c0, a0, st));
    }

    let mut best: Option<(i32, i64, u32, u64, u32)> = None;
    for delta in (-64i64..=256).step_by(8) {
        let base = if delta < 0 {
            meta_reg_va.checked_sub((-delta) as u64)
        } else {
            Some(meta_reg_va + delta as u64)
        };
        let Some(b) = base else { continue };
        let count = bin.read_u32(b).unwrap_or(0);
        if !(64..=2_000_000).contains(&count) {
            continue;
        }
        let array = bin.read_ptr(b + 8).unwrap_or(0);
        let Some(stride) = detect_type_stride(bin, count, array, types) else {
            continue;
        };
        let score = score_types_array(bin, count, array, types, stride);
        if score < 0 {
            continue;
        }
        let dist = (delta - 48).abs();
        let take = match best {
            None => true,
            Some((bs, bd, _, _, _)) => score > bs || (score == bs && dist < bd),
        };
        if take {
            best = Some((score, dist, count, array, stride));
        }
    }
    best.map(|(_, _, c, a, s)| (c, a, s))
}

pub struct AdaptiveTypeResolver<'a> {
    pub bin: &'a BinaryImage,
    pub types: &'a [AdaptiveType],
    pub array_va: u64,
    pub count: u32,
    pub stride: u32,
    pub module_tag: u8,
}

impl<'a> AdaptiveTypeResolver<'a> {
    pub fn resolve_field_type(&self, raw_type_idx: u32) -> AdaptiveFieldTypeInfo {
        if self.array_va == 0 || self.count == 0 || self.stride == 0 {
            return AdaptiveFieldTypeInfo::default();
        }
        let tag = (raw_type_idx >> 24) as u8;
        if self.module_tag != 0 && tag != 0 && tag != self.module_tag {
            return AdaptiveFieldTypeInfo {
                type_name: "object".into(),
                attrs: 0,
                is_static: false,
                resolved: false,
            };
        }
        let idx = crate::metadata::adaptive::resolve_index(raw_type_idx, self.count as usize);
        if idx >= self.count as usize {
            return AdaptiveFieldTypeInfo::default();
        }
        let type_va = self.array_va + idx as u64 * self.stride as u64;
        let Some(bits) = self.bin.read_u32(type_va + 8) else {
            return AdaptiveFieldTypeInfo::default();
        };
        let attrs = (bits & 0xFFFF) as u16;
        let is_static = (attrs & 0x10) != 0;
        let name = self.decode_type_va(type_va, 0);
        let resolved = !name.is_empty();
        AdaptiveFieldTypeInfo {
            type_name: if resolved { name } else { "object".into() },
            attrs,
            is_static,
            resolved,
        }
    }

    pub fn resolve_type_name(&self, raw_type_idx: u32) -> String {
        if raw_type_idx == u32::MAX || self.array_va == 0 || self.count == 0 || self.stride == 0 {
            return "object".into();
        }
        let tag = (raw_type_idx >> 24) as u8;
        if self.module_tag != 0 && tag != 0 && tag != self.module_tag {
            return "object".into();
        }
        let idx = crate::metadata::adaptive::resolve_index(raw_type_idx, self.count as usize);
        if idx >= self.count as usize {
            return "object".into();
        }
        let type_va = self.array_va + idx as u64 * self.stride as u64;
        let s = self.decode_type_va(type_va, 0);
        if s.is_empty() {
            "object".into()
        } else {
            s
        }
    }

    fn decode_type_va(&self, type_va: u64, depth: usize) -> String {
        if type_va == 0 || depth > 6 {
            return String::new();
        }
        let Some(d_val) = self.bin.read_ptr(type_va) else {
            return String::new();
        };
        let Some(bits) = self.bin.read_u32(type_va + 8) else {
            return String::new();
        };
        let kind = ((bits >> 16) & 0xFF) as u8;
        match kind {
            1 => "void".into(),
            2 => "bool".into(),
            3 => "char".into(),
            4 => "sbyte".into(),
            5 => "byte".into(),
            6 => "short".into(),
            7 => "ushort".into(),
            8 => "int".into(),
            9 => "uint".into(),
            10 => "long".into(),
            11 => "ulong".into(),
            12 => "float".into(),
            13 => "double".into(),
            14 => "string".into(),
            22 => "System.TypedReference".into(),
            24 => "IntPtr".into(),
            25 => "UIntPtr".into(),
            28 => "object".into(),
            17 | 18 => {
                let htag = ((d_val >> 24) & 0xFF) as u8;
                let td_idx = (d_val & 0x00FF_FFFF) as usize;
                if self.module_tag != 0 && htag != 0 && htag != self.module_tag {
                    return format!("ExtMod{}_Type_{:04X}", htag, td_idx);
                }
                if let Some(t) = self.types.get(td_idx) {
                    if is_valid_name(&t.name) {
                        return if t.fullname.is_empty() {
                            t.name.clone()
                        } else {
                            t.fullname.clone()
                        };
                    }
                }
                String::new()
            }
            15 => {
                if d_val == 0 {
                    return String::new();
                }
                let inner = self.decode_type_va(d_val, depth + 1);
                if inner.is_empty() {
                    String::new()
                } else {
                    format!("{}*", inner)
                }
            }
            29 => {
                if d_val == 0 {
                    return String::new();
                }
                let inner = self.decode_type_va(d_val, depth + 1);
                if inner.is_empty() {
                    String::new()
                } else {
                    format!("{}[]", inner)
                }
            }
            21 => {
                if d_val == 0 {
                    return String::new();
                }
                let base_h = self.bin.read_ptr(d_val).unwrap_or(0);
                if base_h == 0 {
                    return String::new();
                }
                let btag = ((base_h >> 24) & 0xFF) as u8;
                let base_idx = (base_h & 0x00FF_FFFF) as usize;
                let class_inst = self.bin.read_ptr(d_val + 8).unwrap_or(0);
                let mut args = Vec::new();
                if class_inst != 0 {
                    let argc = self.bin.read_u32(class_inst).unwrap_or(0) as usize;
                    if (1..=16).contains(&argc) {
                        let argv = self.bin.read_ptr(class_inst + 8).unwrap_or(0);
                        if argv != 0 {
                            for i in 0..argc {
                                let arg_va = self.bin.read_ptr(argv + i as u64 * 8).unwrap_or(0);
                                let arg_name = self.decode_type_va(arg_va, depth + 1);
                                if arg_name.is_empty() {
                                    args.clear();
                                    break;
                                }
                                args.push(arg_name);
                            }
                        }
                    }
                }

                let base_name = if self.module_tag != 0 && btag != 0 && btag != self.module_tag {
                    if btag == 1 && base_idx == 0x05DE && args.len() == 1 {
                        "List".to_string()
                    } else if btag == 1 && base_idx == 0x05B5 && args.len() == 2 {
                        "Dictionary".to_string()
                    } else {
                        format!("ExtMod{}_Type_{:04X}", btag, base_idx)
                    }
                } else {
                    let Some(bt) = self.types.get(base_idx) else {
                        return String::new();
                    };
                    if !is_valid_name(&bt.name) {
                        return String::new();
                    }
                    if bt.fullname.is_empty() {
                        bt.name.clone()
                    } else {
                        bt.fullname.clone()
                    }
                };
                if args.is_empty() {
                    base_name
                } else {
                    format!("{}<{}>", base_name, args.join(", "))
                }
            }
            _ => String::new(),
        }
    }
}

pub fn infer_field_type_by_name(name: &str) -> &'static str {
    if name.is_empty() {
        return "object";
    }
    if name.starts_with("m_dic") || name.starts_with("_dic") || name.starts_with("dic") {
        return "Dictionary<object, object>";
    }
    if name.starts_with("m_list") || name.starts_with("_list") || name.starts_with("list") {
        return "List<object>";
    }
    if name.starts_with("m_arr") || name.starts_with("_arr") || name.starts_with("arr") {
        return "object[]";
    }
    if name.starts_with("m_v2") || name.starts_with("v2") {
        return "Vector2";
    }
    if name.starts_with("m_v3")
        || name.starts_with("v3")
        || name.starts_with("m_vPos")
        || name == "m_vPosition"
    {
        return "Vector3";
    }
    if name.starts_with("m_v4") || name.starts_with("v4") {
        return "Vector4";
    }
    if name.starts_with("m_quat") || name.starts_with("m_qRot") {
        return "Quaternion";
    }
    if name.starts_with("m_color") || name.starts_with("m_col") {
        return "Color";
    }

    let lower = name.to_ascii_lowercase();
    let starts_upper_at = |prefix: &str| -> bool {
        name.starts_with(prefix)
            && name
                .as_bytes()
                .get(prefix.len())
                .map(|b| b.is_ascii_uppercase())
                .unwrap_or(false)
    };

    if name.starts_with("m_str")
        || name.starts_with("_str")
        || starts_upper_at("m_s")
        || lower.contains("name")
        || lower.contains("guid")
    {
        return "string";
    }
    if starts_upper_at("m_b")
        || starts_upper_at("_b")
        || starts_upper_at("Is")
        || (starts_upper_at("b") && !name.starts_with("by"))
    {
        return "bool";
    }
    if name.starts_with("m_by") || name.starts_with("by") {
        return "byte";
    }
    if starts_upper_at("m_ui")
        || starts_upper_at("m_u")
        || starts_upper_at("ui")
        || lower.starts_with("icamp")
        || lower.starts_with("ipos")
    {
        return "uint";
    }
    if starts_upper_at("m_ul")
        || starts_upper_at("m_ll")
        || starts_upper_at("m_l")
        || lower.starts_with("luid")
    {
        return "ulong";
    }
    if starts_upper_at("m_i")
        || starts_upper_at("_i")
        || (starts_upper_at("i") && !lower.starts_with("id"))
    {
        return "int";
    }
    if starts_upper_at("m_f") || starts_upper_at("_f") || starts_upper_at("f") {
        return "float";
    }
    if starts_upper_at("m_d") || starts_upper_at("_d") || starts_upper_at("d") {
        return "double";
    }
    "object"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{BinaryFormat, SectionRange};

    #[test]
    fn test_decode_adrp_forward_and_backward() {
        // ADRP X0, +0x1000 from PC=0x1004: imm=+1 => page=(0x1000)+0x1000=0x2000
        // immhi=0, immlo=1 -> bits[30:29]=01 -> 0xB000_0000
        assert_eq!(decode_adrp(0x1004, 0xB000_0000), 0x2000);
        // Negative imm: -1 (21-bit all 1s): immlo=3 (0x6000_0000), immhi=0x7FFFF (0x00FF_FFE0)
        // base 0x9000_0000 | 0x6000_0000 | 0x00FF_FFE0 = 0xF0FF_FFE0 -> page(0x5000) - 0x1000 = 0x4000
        assert_eq!(decode_adrp(0x5004, 0xF0FF_FFE0), 0x4000);
    }

    #[test]
    fn test_infer_field_type_by_name() {
        assert_eq!(infer_field_type_by_name("m_bIsAlive"), "bool");
        assert_eq!(infer_field_type_by_name("m_normalAnimaName"), "string");
        assert_eq!(infer_field_type_by_name("m_vPosition"), "Vector3");
        assert_eq!(infer_field_type_by_name("m_dicPlayers"), "Dictionary<object, object>");
        assert_eq!(infer_field_type_by_name("m_iHp"), "int");
        assert_eq!(infer_field_type_by_name("m_fMoveSpeed"), "float");
    }

    #[test]
    fn test_adaptive_resolver_module_tag_and_null_dval_guard() {
        let mut mem = vec![0u8; 0x100];
        // Il2CppType[0] @ VA 0x1000: kind=21 (GENERICINST), d_val=0 -> must NOT resolve to types[0]
        mem[0..8].copy_from_slice(&0u64.to_le_bytes());
        mem[8..12].copy_from_slice(&(21u32 << 16).to_le_bytes());
        // Il2CppType[1] @ VA 0x1010: kind=18 (CLASS), d_val=0x0300_0001 -> types[1] (MyNs.MyHero)
        mem[0x10..0x18].copy_from_slice(&0x0300_0001u64.to_le_bytes());
        mem[0x18..0x1C].copy_from_slice(&(18u32 << 16).to_le_bytes());
        // Il2CppType[2] @ VA 0x1020: kind=21 (GENERICINST), d_val=0x1040 -> List<MyNs.MyHero>
        mem[0x20..0x28].copy_from_slice(&0x1040u64.to_le_bytes());
        mem[0x28..0x2C].copy_from_slice(&(21u32 << 16).to_le_bytes());
        // Il2CppGenericClass @ 0x1040 (offset 0x40): base_h=0x0100_05DE, class_inst=0x1060
        mem[0x40..0x48].copy_from_slice(&0x0100_05DEu64.to_le_bytes());
        mem[0x48..0x50].copy_from_slice(&0x1060u64.to_le_bytes());
        // Il2CppGenericInst @ 0x1060 (offset 0x60): argc=1, argv=0x1070
        mem[0x60..0x64].copy_from_slice(&1u32.to_le_bytes());
        mem[0x68..0x70].copy_from_slice(&0x1070u64.to_le_bytes());
        // argv[0] @ 0x1070 (offset 0x70) -> 0x1010 (Il2CppType[1])
        mem[0x70..0x78].copy_from_slice(&0x1010u64.to_le_bytes());

        let bin = BinaryImage {
            bytes: mem,
            format: BinaryFormat::Elf,
            is_64bit: true,
            arch: "arm64".into(),
            image_base: 0,
            sections: vec![SectionRange {
                name: ".data".into(),
                va_start: 0x1000,
                va_end: 0x1100,
                file_offset: 0,
                file_size: 0x100,
                is_exec: false,
                is_data: true,
            }],
            relocs: Vec::new(),
            is_memory_dump: false,
            fairplay_encrypted: false,
        };
        let mk_type = |idx: usize, name: &str, ns: &str| AdaptiveType {
            index: idx,
            name: name.into(),
            ns: ns.into(),
            fullname: if ns.is_empty() { name.into() } else { format!("{}.{}", ns, name) },
            token: 0x0200_0001 + idx as u32,
            flags: 0,
            bitfield: 0,
            field_start: 0,
            field_count: 0,
            method_start: 0,
            method_count: 0,
        };
        let types = vec![mk_type(0, "<Module>", ""), mk_type(1, "MyHero", "MyNs")];
        let resolver = AdaptiveTypeResolver {
            bin: &bin,
            types: &types,
            array_va: 0x1000,
            count: 3,
            stride: 16,
            module_tag: 3,
        };

        assert_eq!(resolver.resolve_type_name(0x0300_0000), "object");
        let foreign = resolver.resolve_field_type(0x0100_0001);
        assert_eq!(foreign.type_name, "object");
        assert!(!foreign.resolved);
        assert_eq!(resolver.resolve_type_name(0x0300_0001), "MyNs.MyHero");
        assert_eq!(
            resolver.resolve_type_name(0x0300_0002),
            "List<MyNs.MyHero>"
        );
    }

    #[test]
    fn test_find_arm64_plt_stub_for_got() {
        // Test standard ADRP X16 + LDR X17 and BTI c + ADRP X16 + LDR X17 stubs
        // Code section at VA 0x1000..0x1020:
        // +0x00 (VA 0x1000): ADRP X16, page(0x3000) -> delta=+2 pages -> immlo=2 (0x4000_0000), rd=16 -> 0xD000_0010
        // +0x04 (VA 0x1004): LDR X17, [X16, #0x10] -> imm12=2 -> 0xF940_0211 | (2 << 10) = 0xF940_0A11
        //   => GOT = 0x3000 + 0x10 = 0x3010 (stub should be 0x1000)
        // +0x08 (VA 0x1008): BTI c -> 0xD503_245F
        // +0x0C (VA 0x100C): ADRP X16, page(0x4000) -> delta=+3 pages -> immlo=3 (0x6000_0000), rd=16 -> 0xF000_0010
        // +0x10 (VA 0x1010): LDR X17, [X16, #0x20] -> imm12=4 -> 0xF940_0211 | (4 << 10) = 0xF940_1211
        //   => GOT = 0x4000 + 0x20 = 0x4020 (stub should be 0x1008 due to BTI c)
        let mut code = vec![0u8; 0x20];
        let insns: [u32; 5] = [0xD000_0010, 0xF940_0A11, 0xD503_245F, 0xF000_0010, 0xF940_1211];
        for (idx, insn) in insns.iter().enumerate() {
            code[idx * 4..idx * 4 + 4].copy_from_slice(&insn.to_le_bytes());
        }
        let bin = BinaryImage {
            bytes: code,
            format: BinaryFormat::Elf,
            is_64bit: true,
            arch: "arm64".into(),
            image_base: 0,
            sections: vec![SectionRange {
                name: "PT_LOAD_EXEC".into(),
                va_start: 0x1000,
                va_end: 0x1020,
                file_offset: 0,
                file_size: 0x20,
                is_exec: true,
                is_data: false,
            }],
            relocs: Vec::new(),
            is_memory_dump: false,
            fairplay_encrypted: false,
        };
        assert_eq!(find_arm64_plt_stub_for_got(&bin, 0x3010), Some(0x1000));
        assert_eq!(find_arm64_plt_stub_for_got(&bin, 0x4020), Some(0x1008));
        assert_eq!(find_arm64_plt_stub_for_got(&bin, 0x5000), None);
    }
}
