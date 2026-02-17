use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipEncryption {
    None,
    Aes,
    ZipCrypto,
    Unknown,
}

pub fn inspect_zip_encryption(path: &Path) -> Result<ZipEncryption> {
    let data = fs::read(path).with_context(|| format!("unable to read zip: {}", path.display()))?;
    inspect_zip_encryption_bytes(&data)
}

pub fn inspect_zip_encryption_bytes(data: &[u8]) -> Result<ZipEncryption> {
    // Locate End of Central Directory (EOCD): 0x06054b50.
    // EOCD can be up to 64k + 22 bytes from end (comment field).
    let search_start = data.len().saturating_sub(22 + 65535);
    let mut eocd_pos = None;
    for i in (search_start..data.len().saturating_sub(3)).rev() {
        if data[i..].starts_with(&[0x50, 0x4b, 0x05, 0x06]) {
            eocd_pos = Some(i);
            break;
        }
    }
    let eocd = eocd_pos.ok_or_else(|| anyhow!("not a zip (missing EOCD)"))?;
    if eocd + 22 > data.len() {
        return Err(anyhow!("truncated EOCD"));
    }

    let cd_size = le_u32(&data[eocd + 12..eocd + 16]) as usize;
    let cd_offset = le_u32(&data[eocd + 16..eocd + 20]) as usize;
    if cd_offset + cd_size > data.len() {
        return Err(anyhow!("central directory out of range"));
    }

    let cd = &data[cd_offset..cd_offset + cd_size];
    let mut pos = 0usize;
    let mut any_encrypted = false;
    let mut any_aes = false;

    while pos + 46 <= cd.len() {
        if !cd[pos..].starts_with(&[0x50, 0x4b, 0x01, 0x02]) {
            break;
        }
        // Central directory file header structure.
        let gp_flag = le_u16(&cd[pos + 8..pos + 10]);
        let file_name_len = le_u16(&cd[pos + 28..pos + 30]) as usize;
        let extra_len = le_u16(&cd[pos + 30..pos + 32]) as usize;
        let comment_len = le_u16(&cd[pos + 32..pos + 34]) as usize;

        let header_len = 46 + file_name_len + extra_len + comment_len;
        if pos + header_len > cd.len() {
            break;
        }

        let encrypted = (gp_flag & 0x0001) != 0;
        if encrypted {
            any_encrypted = true;
            let extra = &cd[pos + 46 + file_name_len..pos + 46 + file_name_len + extra_len];
            if has_aes_extra(extra) {
                any_aes = true;
            }
        }

        pos += header_len;
    }

    if !any_encrypted {
        return Ok(ZipEncryption::None);
    }
    if any_aes {
        return Ok(ZipEncryption::Aes);
    }

    // For MVP: if encrypted and no AES marker, assume legacy ZipCrypto.
    Ok(ZipEncryption::ZipCrypto)
}

fn has_aes_extra(extra: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let header_id = le_u16(&extra[pos..pos + 2]);
        let data_size = le_u16(&extra[pos + 2..pos + 4]) as usize;
        pos += 4;
        if pos + data_size > extra.len() {
            break;
        }
        if header_id == 0x9901 {
            return true;
        }
        pos += data_size;
    }
    false
}

fn le_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
