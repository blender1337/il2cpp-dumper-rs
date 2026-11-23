#![allow(dead_code)]

use anyhow::Result;

#[derive(Debug, Clone, Copy)]
pub struct TableRef {
    pub start: usize,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct AdaptiveImage {
    pub name: String,
    pub type_start: usize,
    pub type_count: usize,
}

#[derive(Debug, Clone)]
pub struct AdaptiveType {
    pub index: usize,
    pub name: String,
    pub ns: String,
    pub fullname: String,
    pub token: u32,
    pub flags: u32,
    pub bitfield: u32,
    pub field_start: usize,
    pub field_count: u16,
    pub method_start: usize,
    pub method_count: u16,
}

impl AdaptiveType {
    pub fn is_valuetype(&self) -> bool {
        (self.bitfield & 1) != 0
    }
    pub fn is_enum(&self) -> bool {
        (self.bitfield & 2) != 0
    }
}

#[derive(Debug, Clone)]
pub struct AdaptiveField {
    pub name: String,
    pub type_idx_raw: u32,
    pub token: u32,
}

#[derive(Debug, Clone)]
pub struct AdaptiveMethod {
    pub name: String,
    pub return_type_raw: u32,
    pub param_start: usize,
    pub param_count: u16,
    pub token: u32,
    pub flags: u16,
    pub slot: u16,
}

#[derive(Debug, Clone)]
pub struct AdaptiveParam {
    pub name: String,
    pub type_idx_raw: u32,
}

#[derive(Debug, Clone)]
pub struct AdaptiveMetadata {
    pub version: i32,
    pub layout_summary: String,
    pub module_tag: u8,
    pub images: Vec<AdaptiveImage>,
    pub types: Vec<AdaptiveType>,
    pub fields: Vec<AdaptiveField>,
    pub methods: Vec<AdaptiveMethod>,
    pub params: Vec<AdaptiveParam>,
}

fn r_u32(d: &[u8], off: usize) -> Option<u32> {
    let b = d.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn r_u16(d: &[u8], off: usize) -> Option<u16> {
    let b = d.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

pub fn decode_tagged(raw: u32) -> usize {
    if raw == u32::MAX {
        return 0;
    }
    let high = raw >> 24;
    if high <= 3 {
        (raw & 0x00FF_FFFF) as usize
    } else {
        raw as usize
    }
}

pub fn resolve_index(raw: u32, limit: usize) -> usize {
    if raw == u32::MAX || limit == 0 {
        return 0;
    }
    let masked = (raw & 0x00FF_FFFF) as usize;
    if masked < limit {
        masked
    } else if (raw as usize) < limit {
        raw as usize
    } else {
        masked
    }
}

pub fn is_chain_header(data: &[u8]) -> bool {
    parse_chain_tables(data)
        .map(|t| t.len() >= 16)
        .unwrap_or(false)
}

pub fn parse_chain_tables(data: &[u8]) -> Option<Vec<TableRef>> {
    if data.len() < 16 {
        return None;
    }
    let magic = r_u32(data, 0)?;
    if magic != crate::metadata::header::METADATA_MAGIC {
        return None;
    }

    let max_pairs = 128.min((data.len() - 8) / 8);
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    let mut prev_end: Option<usize> = None;

    for i in 0..max_pairs {
        let a = r_u32(data, 8 + i * 8)? as usize;
        let b = r_u32(data, 12 + i * 8)? as usize;
        if b < 16 || b > data.len() {
            break;
        }
        if let Some(p) = prev_end {
            if b <= p || p.saturating_add(a) != b {
                break;
            }
        }
        pairs.push((a, b));
        prev_end = Some(b);
    }

    if pairs.len() < 4 {
        return None;
    }

    let header_end = 8 + pairs.len() * 8;
    let first_end = pairs[0].1;
    let last_end = pairs.last()?.1;
    if first_end < header_end || last_end > data.len() {
        return None;
    }
    if data.len() - last_end > data.len() / 2 {
        return None;
    }

    let mut tabs = Vec::with_capacity(pairs.len());
    tabs.push(TableRef {
        start: header_end,
        size: first_end - header_end,
    });
    for i in 1..pairs.len() {
        tabs.push(TableRef {
            start: pairs[i - 1].1,
            size: pairs[i].0,
        });
    }
    Some(tabs)
}

fn looks_like_strings(d: &[u8], t: TableRef) -> bool {
    if t.size < 64 || t.start.saturating_add(t.size) > d.len() {
        return false;
    }
    let sample = &d[t.start..t.start + t.size.min(65536)];
    let mut zeros = 0usize;
    let mut printable = 0usize;
    for &c in sample {
        if c == 0 {
            zeros += 1;
        } else if (0x20..0x7F).contains(&c) || c >= 0x80 {
            printable += 1;
        }
    }
    zeros > sample.len() / 200 && printable >= sample.len() / 2
}

fn find_string_table(d: &[u8], tabs: &[TableRef]) -> Option<usize> {
    if tabs.len() > 3 && looks_like_strings(d, tabs[3]) {
        return Some(3);
    }
    let mut best = None;
    let mut best_sz = 0usize;
    for (i, &t) in tabs.iter().enumerate().skip(1) {
        if looks_like_strings(d, t) && t.size > best_sz {
            best_sz = t.size;
            best = Some(i);
        }
    }
    best
}

pub fn read_str_at(d: &[u8], sbase: usize, ssize: usize, raw: u32) -> String {
    if ssize == 0 || sbase >= d.len() {
        return String::new();
    }
    let off = decode_tagged(raw);
    if off >= ssize {
        return String::new();
    }
    let p = sbase + off;
    if p >= d.len() {
        return String::new();
    }
    let limit = d.len().min(sbase + ssize);
    let mut start = p;
    while start > sbase && d[start - 1] != 0 {
        start -= 1;
    }
    let mut end = start;
    while end < limit && d[end] != 0 && end - start < 1024 {
        end += 1;
    }
    if end <= start {
        return String::new();
    }
    String::from_utf8_lossy(&d[start..end]).into_owned()
}

pub fn is_valid_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 1024 {
        return false;
    }
    let b = s.as_bytes();
    let f = b[0];
    if !(f.is_ascii_alphabetic() || matches!(f, b'_' | b'<' | b'$' | b'.')) {
        return false;
    }
    b.iter().all(|&c| {
        c.is_ascii_alphanumeric()
            || matches!(c, b'_' | b'.' | b'<' | b'>' | b'$' | b'`' | b'-' | b'[' | b']' | b'/')
    })
}

fn sample_indices(count: usize, limit: usize) -> Vec<usize> {
    let n = count.min(limit);
    if n == count {
        (0..count).collect()
    } else {
        (0..n).map(|i| (i * count) / n).collect()
    }
}

#[allow(clippy::too_many_arguments)]
fn record_score(
    d: &[u8],
    t: TableRef,
    sbase: usize,
    ssize: usize,
    stride: usize,
    name_off: usize,
    token_off: usize,
    token_class: u8,
) -> Option<i32> {
    if t.size == 0 || !t.size.is_multiple_of(stride) {
        return None;
    }
    let count = t.size / stride;
    if count == 0 {
        return None;
    }
    let ps = sample_indices(count, 64);
    let mut names = 0usize;
    let mut tokens = 0usize;
    for &i in &ps {
        let off = t.start + i * stride;
        let raw_name = r_u32(d, off + name_off)?;
        if is_valid_name(&read_str_at(d, sbase, ssize, raw_name)) {
            names += 1;
        }
        let tok = r_u32(d, off + token_off)?;
        if (tok >> 24) as u8 == token_class {
            tokens += 1;
        }
    }
    let n = ps.len();
    if names * 4 < n * 3 || tokens * 4 < n * 3 {
        return None;
    }
    Some((names * 100 / n + tokens * 100 / n) as i32)
}

fn chain_ok(
    d: &[u8],
    t: TableRef,
    stride: usize,
    start_off: usize,
    count_off: usize,
    want_sum: usize,
) -> bool {
    if stride == 0 || !t.size.is_multiple_of(stride) {
        return false;
    }
    let count = t.size / stride;
    let mut prev: Option<usize> = None;
    let mut total = 0usize;
    for i in 0..count {
        let off = t.start + i * stride;
        let Some(raw_start) = r_u32(d, off + start_off) else {
            return false;
        };
        let Some(n) = r_u16(d, off + count_off) else {
            return false;
        };
        let n_us = n as usize;
        total += n_us;
        if total > want_sum {
            return false;
        }
        if raw_start == u32::MAX || n == 0 {
            prev = None;
            continue;
        }
        let high = raw_start >> 24;
        let val = if high == 0 || high == 3 {
            (raw_start & 0x00FF_FFFF) as usize
        } else {
            raw_start as usize
        };
        if let Some(p) = prev {
            if val != p {
                return false;
            }
        }
        prev = Some(val + n_us);
    }
    total == want_sum
}

fn image_score(
    d: &[u8],
    t: TableRef,
    sbase: usize,
    ssize: usize,
    stride: usize,
    name_off: usize,
    type_total: usize,
) -> Option<i32> {
    if t.size == 0 || stride < 16 || !t.size.is_multiple_of(stride) {
        return None;
    }
    let count = t.size / stride;
    if count == 0 || count > 4096 {
        return None;
    }
    let checked = count.min(8);
    let mut dll = 0usize;
    for i in 0..checked {
        let off = t.start + i * stride;
        let raw_name = r_u32(d, off + name_off)?;
        let s = read_str_at(d, sbase, ssize, raw_name).to_ascii_lowercase();
        if s.len() > 4 && s.contains(".dll") {
            dll += 1;
        }
    }
    if dll * 2 < checked {
        return None;
    }
    let mut total = 0usize;
    for i in 0..count {
        let off = t.start + i * stride;
        let raw_ts = r_u32(d, off + 8)?;
        let ts = if (raw_ts >> 24) == 0 || (raw_ts >> 24) == 3 {
            (raw_ts & 0x00FF_FFFF) as usize
        } else {
            raw_ts as usize
        };
        let tc = r_u32(d, off + 12)? as usize;
        if ts != total {
            return None;
        }
        total += tc;
    }
    if total != type_total {
        return None;
    }
    Some((dll * 100 / checked + 100) as i32)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CandKey {
    neg_score: i32,
    idx_dist: usize,
    stride_dist: usize,
    stride: usize,
}

impl AdaptiveMetadata {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let version = r_u32(data, 4).unwrap_or(0) as i32;
        let tabs = parse_chain_tables(data)
            .ok_or_else(|| anyhow::anyhow!("Not a valid chain-header metadata file"))?;
        let str_idx = find_string_table(data, &tabs)
            .ok_or_else(|| anyhow::anyhow!("String table not found in adaptive metadata"))?;
        let sbase = tabs[str_idx].start;
        let ssize = tabs[str_idx].size;

        // Detect Methods, Fields, Types, Images (starting with canonical name_off = 0, then fallback 4..=32)
        let mut detected = None;
        for name_off in (0..=32).step_by(4) {
            if let Some(layout) = Self::detect_layout(data, &tabs, sbase, ssize, name_off) {
                detected = Some(layout);
                break;
            }
        }
        let (m_idx, m_stride, m_name_off, m_tok_off, f_idx, f_stride, f_name_off, f_tok_off, t_idx, t_stride, t_name_off, t_tok_off, fs_off, fc_off, ms_off, mc_off, i_idx, i_stride, i_name_off, canonical) =
            detected.ok_or_else(|| anyhow::anyhow!("Failed to detect adaptive metadata table layout"))?;

        let method_total = tabs[m_idx].size / m_stride;
        let field_total = tabs[f_idx].size / f_stride;

        // Locate optional Parameters table (token class 0x08) for richer signatures
        let param_loc = Self::find_param_table(data, &tabs, sbase, ssize);

        // Parse Images
        let itab = tabs[i_idx];
        let img_count = itab.size / i_stride;
        let mut images = Vec::with_capacity(img_count);
        for i in 0..img_count {
            let off = itab.start + i * i_stride;
            let name = r_u32(data, off + i_name_off)
                .map(|r| read_str_at(data, sbase, ssize, r))
                .unwrap_or_default();
            let raw_ts = r_u32(data, off + 8).unwrap_or(0);
            let type_start = decode_tagged(raw_ts);
            let type_count = r_u32(data, off + 12).unwrap_or(0) as usize;
            images.push(AdaptiveImage {
                name,
                type_start,
                type_count,
            });
        }

        // Parse Fields
        let ftab = tabs[f_idx];
        let f_type_off = f_name_off + 4;
        let mut fields = Vec::with_capacity(field_total);
        for i in 0..field_total {
            let off = ftab.start + i * f_stride;
            let raw_name = r_u32(data, off + f_name_off).unwrap_or(0);
            let type_idx_raw = r_u32(data, off + f_type_off).unwrap_or(0);
            let token = r_u32(data, off + f_tok_off).unwrap_or(0);
            let mut name = read_str_at(data, sbase, ssize, raw_name);
            if !is_valid_name(&name) {
                let low = if token != 0 { token & 0xFFFF } else { (i + 1) as u32 };
                name = format!("field_{:04X}", low);
            }
            fields.push(AdaptiveField {
                name,
                type_idx_raw,
                token,
            });
        }

        // Parse Methods
        let mtab = tabs[m_idx];
        let flags_off = if m_tok_off + 2 <= m_stride { m_tok_off + 4 } else { m_stride - 2 };
        let slot_off = if m_tok_off + 8 < m_stride { m_tok_off + 8 } else { m_stride - 4 };
        let param_cnt_off = if m_tok_off + 12 <= m_stride { m_tok_off + 10 } else { m_stride - 2 };
        let mut methods = Vec::with_capacity(method_total);
        for i in 0..method_total {
            let off = mtab.start + i * m_stride;
            let raw_name = r_u32(data, off + m_name_off).unwrap_or(0);
            let return_type_raw = r_u32(data, off + m_name_off + 8).unwrap_or(0);
            let raw_pstart = r_u32(data, off + m_name_off + 12).unwrap_or(u32::MAX);
            let token = r_u32(data, off + m_tok_off).unwrap_or(0);
            let flags = r_u16(data, off + flags_off).unwrap_or(0);
            let slot = r_u16(data, off + slot_off).unwrap_or(u16::MAX);
            let param_count = r_u16(data, off + param_cnt_off).unwrap_or(0);
            let mut name = read_str_at(data, sbase, ssize, raw_name);
            if !is_valid_name(&name) {
                let low = if token != 0 { token & 0xFFFF } else { (i + 1) as u32 };
                name = format!("Method_{:04X}", low);
            }
            methods.push(AdaptiveMethod {
                name,
                return_type_raw,
                param_start: if raw_pstart == u32::MAX { usize::MAX } else { decode_tagged(raw_pstart) },
                param_count,
                token,
                flags,
                slot,
            });
        }

        // Parse Parameters (if found)
        let mut params = Vec::new();
        if let Some((p_idx, p_stride)) = param_loc {
            let ptab = tabs[p_idx];
            let pcount = ptab.size / p_stride;
            params.reserve(pcount);
            for i in 0..pcount {
                let off = ptab.start + i * p_stride;
                let rname = r_u32(data, off).unwrap_or(0);
                let type_idx_raw = r_u32(data, off + p_stride - 4).unwrap_or(0);
                let name = read_str_at(data, sbase, ssize, rname);
                params.push(AdaptiveParam { name, type_idx_raw });
            }
        }

        // Parse Types
        let ttab = tabs[t_idx];
        let type_total = ttab.size / t_stride;
        let t_ns_off = t_name_off + 4;
        let t_flags_off = fs_off.saturating_sub(4);
        let t_bitfield_off = t_tok_off.saturating_sub(4);
        let mut types = Vec::with_capacity(type_total);
        let mut tag_counts = [0usize; 16];
        let mut sampled_tags = 0usize;
        for i in 0..type_total {
            let off = ttab.start + i * t_stride;
            let raw_name = r_u32(data, off + t_name_off).unwrap_or(0);
            let raw_ns = r_u32(data, off + t_ns_off).unwrap_or(0);
            let token = r_u32(data, off + t_tok_off).unwrap_or(0);
            let mut name = read_str_at(data, sbase, ssize, raw_name);
            if !is_valid_name(&name) {
                let low = if token != 0 { token & 0xFFFF } else { (i + 1) as u32 };
                name = format!("Type_{:04X}", low);
            }
            let mut ns = read_str_at(data, sbase, ssize, raw_ns);
            if ns == "ty" {
                ns.clear();
            }
            let fullname = if ns.is_empty() {
                name.clone()
            } else {
                format!("{}.{}", ns, name)
            };
            let raw_fs = r_u32(data, off + fs_off).unwrap_or(u32::MAX);
            let field_count = r_u16(data, off + fc_off).unwrap_or(0);
            if sampled_tags < 512 && field_count > 0 && raw_fs != u32::MAX {
                let tag = (raw_fs >> 24) as usize;
                if (1..=15).contains(&tag) {
                    tag_counts[tag] += 1;
                }
                sampled_tags += 1;
            }
            let field_start = resolve_index(raw_fs, field_total);
            let method_start = resolve_index(r_u32(data, off + ms_off).unwrap_or(u32::MAX), method_total);
            let method_count = r_u16(data, off + mc_off).unwrap_or(0);
            let flags = r_u32(data, off + t_flags_off).unwrap_or(0);
            let bitfield = r_u32(data, off + t_bitfield_off).unwrap_or(0);

            types.push(AdaptiveType {
                index: i,
                name,
                ns,
                fullname,
                token,
                flags,
                bitfield,
                field_start,
                field_count,
                method_start,
                method_count,
            });
        }

        let module_tag = if sampled_tags > 0 {
            tag_counts
                .iter()
                .enumerate()
                .skip(1)
                .max_by_key(|&(_, &c)| c)
                .filter(|&(_, &c)| c * 2 > sampled_tags)
                .map(|(t, _)| t as u8)
                .unwrap_or(0)
        } else {
            0
        };

        let layout_summary = format!(
            "tables m{}/f{}/t{}/i{} str{} | methods stride {} (token +{}), fields stride {} (token +{}), types stride {} (token +{}, fs +{}, fc +{}, ms +{}, mc +{}), images stride {} | totals {}/{}/{} | canonical={}",
            m_idx, f_idx, t_idx, i_idx, str_idx,
            m_stride, m_tok_off,
            f_stride, f_tok_off,
            t_stride, t_tok_off, fs_off, fc_off, ms_off, mc_off,
            i_stride,
            method_total, field_total, type_total, canonical
        );

        Ok(Self {
            version,
            layout_summary,
            module_tag,
            images,
            types,
            fields,
            methods,
            params,
        })
    }

    fn find_param_table(d: &[u8], tabs: &[TableRef], sbase: usize, ssize: usize) -> Option<(usize, usize)> {
        let mut best: Option<(CandKey, usize, usize)> = None;
        for (idx, &t) in tabs.iter().enumerate().skip(1) {
            for stride in (12..=24).step_by(4) {
                if let Some(score) = record_score(d, t, sbase, ssize, stride, 0, 4, 0x08) {
                    let key = CandKey {
                        neg_score: -score,
                        idx_dist: idx.abs_diff(11),
                        stride_dist: stride.abs_diff(12),
                        stride,
                    };
                    if best.as_ref().map(|b| key < b.0).unwrap_or(true) {
                        best = Some((key, idx, stride));
                    }
                }
            }
        }
        best.map(|(_, idx, stride)| (idx, stride))
    }

    #[allow(clippy::type_complexity)]
    fn detect_layout(
        d: &[u8],
        tabs: &[TableRef],
        sbase: usize,
        ssize: usize,
        name_off: usize,
    ) -> Option<(usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, usize, bool)> {
        // Fast canonical check first (when name_off == 0)
        if name_off == 0 && tabs.len() >= 22 {
            let (m_sz, f_sz, t_sz, i_sz) = (tabs[6].size, tabs[12].size, tabs[20].size, tabs[21].size);
            if m_sz % 32 == 0 && f_sz % 12 == 0 && t_sz % 92 == 0 && i_sz % 40 == 0 {
                let mt = m_sz / 32;
                let ft = f_sz / 12;
                let tt = t_sz / 92;
                if record_score(d, tabs[6], sbase, ssize, 32, 0, 20, 0x06).is_some()
                    && record_score(d, tabs[12], sbase, ssize, 12, 0, 8, 0x04).is_some()
                    && record_score(d, tabs[20], sbase, ssize, 92, 0, 88, 0x02).is_some()
                    && chain_ok(d, tabs[20], 92, 36, 72, ft)
                    && chain_ok(d, tabs[20], 92, 40, 68, mt)
                    && image_score(d, tabs[21], sbase, ssize, 40, 0, tt).is_some()
                {
                    return Some((6, 32, 0, 20, 12, 12, 0, 8, 20, 92, 0, 88, 36, 72, 40, 68, 21, 40, 0, true));
                }
            }
        }

        // General heuristic search
        let mut best_m: Option<(CandKey, usize, usize, usize)> = None;
        for (idx, &t) in tabs.iter().enumerate().skip(1) {
            for stride in (32..=192).step_by(4) {
                if t.size == 0 || t.size % stride != 0 {
                    continue;
                }
                let cnt = t.size / stride;
                if cnt == 0 || cnt > 4_000_000 || name_off + 4 > stride {
                    continue;
                }
                for tok_off in (0..=stride - 4).step_by(4) {
                    if tok_off == name_off {
                        continue;
                    }
                    if let Some(sc) = record_score(d, t, sbase, ssize, stride, name_off, tok_off, 0x06) {
                        let key = CandKey {
                            neg_score: -sc,
                            idx_dist: idx.abs_diff(6),
                            stride_dist: stride.abs_diff(32),
                            stride,
                        };
                        if best_m.as_ref().map(|b| key < b.0).unwrap_or(true) {
                            best_m = Some((key, idx, stride, tok_off));
                        }
                    }
                }
            }
        }
        let (_, m_idx, m_stride, m_tok_off) = best_m?;

        let mut best_f: Option<(CandKey, usize, usize, usize)> = None;
        let f_type_off = name_off + 4;
        for (idx, &t) in tabs.iter().enumerate().skip(1) {
            for stride in (12..=64).step_by(4) {
                if t.size == 0 || t.size % stride != 0 {
                    continue;
                }
                let cnt = t.size / stride;
                if cnt == 0 || cnt > 4_000_000 || f_type_off + 4 > stride {
                    continue;
                }
                for tok_off in (0..=stride - 4).step_by(4) {
                    if tok_off == name_off || tok_off == f_type_off {
                        continue;
                    }
                    if let Some(sc) = record_score(d, t, sbase, ssize, stride, name_off, tok_off, 0x04) {
                        let key = CandKey {
                            neg_score: -sc,
                            idx_dist: idx.abs_diff(12),
                            stride_dist: stride.abs_diff(12),
                            stride,
                        };
                        if best_f.as_ref().map(|b| key < b.0).unwrap_or(true) {
                            best_f = Some((key, idx, stride, tok_off));
                        }
                    }
                }
            }
        }
        let (_, f_idx, f_stride, f_tok_off) = best_f?;

        let method_total = tabs[m_idx].size / m_stride;
        let field_total = tabs[f_idx].size / f_stride;

        let mut best_t: Option<(CandKey, usize, usize, usize, usize, usize, usize, usize)> = None;
        let ns_off = name_off + 4;
        for (idx, &t) in tabs.iter().enumerate().skip(1) {
            for stride in (92..=256).step_by(4) {
                if t.size == 0 || t.size % stride != 0 {
                    continue;
                }
                let count = t.size / stride;
                if count == 0 || count > 2_000_000 || ns_off + 4 > stride {
                    continue;
                }
                let ps = sample_indices(count, 64);
                let mut found_tok = None;
                for off in (0..=stride - 4).step_by(4) {
                    if off == name_off || off == ns_off {
                        continue;
                    }
                    let hits = ps
                        .iter()
                        .filter(|&&pi| {
                            r_u32(d, t.start + pi * stride + off)
                                .map(|tok| (tok >> 24) == 0x02)
                                .unwrap_or(false)
                        })
                        .count();
                    if hits * 4 >= ps.len() * 3 {
                        found_tok = Some(off);
                        break;
                    }
                }
                let Some(tok_off) = found_tok else { continue };
                let Some(base_sc) = record_score(d, t, sbase, ssize, stride, name_off, tok_off, 0x02) else {
                    continue;
                };

                let mut sums16 = vec![0usize; stride];
                for i in 0..count {
                    let rec_off = t.start + i * stride;
                    for c in (0..=stride - 2).step_by(2) {
                        sums16[c] += r_u16(d, rec_off + c).unwrap_or(0) as usize;
                    }
                }
                let fcounts: Vec<usize> = (0..=stride - 2).step_by(2).filter(|&c| sums16[c] == field_total).collect();
                let mcounts: Vec<usize> = (0..=stride - 2).step_by(2).filter(|&c| sums16[c] == method_total).collect();

                for &fc in &fcounts {
                    for fs in (0..=stride - 4).step_by(4) {
                        if fs == fc || !chain_ok(d, t, stride, fs, fc, field_total) {
                            continue;
                        }
                        for &mc in &mcounts {
                            if mc == fc || mc == fs {
                                continue;
                            }
                            for ms in (0..=stride - 4).step_by(4) {
                                if ms == fs || ms == fc || ms == mc || !chain_ok(d, t, stride, ms, mc, method_total) {
                                    continue;
                                }
                                let key = CandKey {
                                    neg_score: -base_sc,
                                    idx_dist: idx.abs_diff(20),
                                    stride_dist: stride.abs_diff(92),
                                    stride,
                                };
                                if best_t.as_ref().map(|b| key < b.0).unwrap_or(true) {
                                    best_t = Some((key, idx, stride, tok_off, fs, fc, ms, mc));
                                }
                            }
                        }
                    }
                }
            }
        }
        let (_, t_idx, t_stride, t_tok_off, fs_off, fc_off, ms_off, mc_off) = best_t?;
        let type_total = tabs[t_idx].size / t_stride;

        let mut best_i: Option<(CandKey, usize, usize)> = None;
        for (idx, &t) in tabs.iter().enumerate().skip(1) {
            for stride in (40..=128).step_by(8) {
                if let Some(sc) = image_score(d, t, sbase, ssize, stride, name_off, type_total) {
                    let key = CandKey {
                        neg_score: -sc,
                        idx_dist: idx.abs_diff(21),
                        stride_dist: stride.abs_diff(40),
                        stride,
                    };
                    if best_i.as_ref().map(|b| key < b.0).unwrap_or(true) {
                        best_i = Some((key, idx, stride));
                    }
                }
            }
        }
        let (_, i_idx, i_stride) = best_i?;

        Some((
            m_idx, m_stride, name_off, m_tok_off, f_idx, f_stride, name_off, f_tok_off, t_idx, t_stride,
            name_off, t_tok_off, fs_off, fc_off, ms_off, mc_off, i_idx, i_stride, name_off, false,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_tagged_and_chain_header() {
        assert_eq!(decode_tagged(0x0100_0055), 0x55);
        assert_eq!(decode_tagged(0x0300_1234), 0x1234);
        assert_eq!(decode_tagged(0x1000_0020), 0x1000_0020);

        let mut buf = vec![0u8; 380];
        buf[0..4].copy_from_slice(&crate::metadata::header::METADATA_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&1024i32.to_le_bytes());
        // Build 16 chained tables starting after 8 + 16*8 = 136 bytes
        let mut end = 140u32;
        for i in 0..16u32 {
            let sz = if i == 0 { 0u32 } else { 16 };
            if i > 0 {
                end += sz;
            }
            let off = 8 + (i as usize) * 8;
            buf[off..off + 4].copy_from_slice(&sz.to_le_bytes());
            buf[off + 4..off + 8].copy_from_slice(&end.to_le_bytes());
        }
        assert!(is_chain_header(&buf));
        let tabs = parse_chain_tables(&buf).unwrap();
        assert_eq!(tabs.len(), 16);
        assert_eq!(tabs[1].size, 16);
    }
}
