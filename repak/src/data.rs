use std::io::Write;

use crate::{
    entry::{Block, Entry},
    Compression, Error, Hash, Version, VersionMajor,
};

type Result<T, E = Error> = std::result::Result<T, E>;

pub struct PartialEntry<D: AsRef<[u8]>> {
    compression: Option<Compression>,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_block_size: u32,
    data: PartialEntryData<D>,
    hash: Hash,
}
pub(crate) struct PartialBlock {
    uncompressed_size: usize,
    data: Vec<u8>,
}
pub(crate) enum PartialEntryData<D> {
    Slice(D),
    Blocks(Vec<PartialBlock>),
}

#[cfg(feature = "compression")]
pub(crate) fn get_compression_slot(
    version: Version,
    compression_slots: &mut Vec<Option<Compression>>,
    compression: Compression,
) -> Result<u32> {
    let slot = compression_slots
        .iter()
        .enumerate()
        .find(|(_, s)| **s == Some(compression));
    Ok(if let Some((i, _)) = slot {
        // existing found
        i
    } else {
        if version.version_major() < VersionMajor::FNameBasedCompression {
            return Err(Error::Other(format!(
                "cannot use {compression:?} prior to FNameBasedCompression (pak version 8)"
            )));
        }

        // find empty slot
        if let Some((i, empty_slot)) = compression_slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.is_none())
        {
            // empty found, set it to used compression type
            *empty_slot = Some(compression);
            i
        } else {
            // no empty slot found, add a new one
            compression_slots.push(Some(compression));
            compression_slots.len() - 1
        }
    } as u32)
}

impl<D: AsRef<[u8]>> PartialEntry<D> {
    pub(crate) fn build_entry(
        &self,
        version: Version,
        #[allow(unused)] compression_slots: &mut Vec<Option<Compression>>,
        file_offset: u64,
    ) -> Result<Entry> {
        #[cfg(feature = "compression")]
        let compression_slot = self
            .compression
            .map(|c| get_compression_slot(version, compression_slots, c))
            .transpose()?;
        #[cfg(not(feature = "compression"))]
        let compression_slot = None;

        assert!(
            compression_slot.is_none()
                || !matches!(&self.data, PartialEntryData::Blocks(b) if b.is_empty()),
            "compressed entry must have at least one block"
        );

        let blocks = match &self.data {
            PartialEntryData::Slice(_) => None,
            PartialEntryData::Blocks(blocks) => {
                let entry_size =
                    Entry::get_serialized_size(version, compression_slot, blocks.len() as u32);

                let mut offset = entry_size;
                if version.version_major() < VersionMajor::RelativeChunkOffsets {
                    offset += file_offset;
                };

                Some(
                    blocks
                        .iter()
                        .map(|block| {
                            let start = offset;
                            offset += block.data.len() as u64;
                            let end = offset;
                            Block { start, end }
                        })
                        .collect(),
                )
            }
        };

        Ok(Entry {
            offset: file_offset,
            compressed: self.compressed_size,
            uncompressed: self.uncompressed_size,
            compression_slot,
            timestamp: None,
            hash: Some(self.hash),
            blocks,
            flags: 0,
            compression_block_size: self.compression_block_size,
        })
    }
    pub(crate) fn write_data<S: Write>(&self, stream: &mut S) -> Result<()> {
        match &self.data {
            PartialEntryData::Slice(data) => {
                stream.write_all(data.as_ref())?;
            }
            PartialEntryData::Blocks(blocks) => {
                for block in blocks {
                    stream.write_all(&block.data)?;
                }
            }
        }
        Ok(())
    }
}

/// Oodle compressor family used when writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OodleCompressor {
    Kraken,
    #[default]
    Mermaid,
    Selkie,
    Leviathan,
    Hydra,
}

/// Per-method compression settings for writing. Defaults reproduce repak's
/// historical output (zlib/gzip level 1, zstd default level, Oodle Mermaid
/// at Normal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionOptions {
    /// 0–9
    pub zlib_level: u32,
    /// 0–9
    pub gzip_level: u32,
    /// 1–22; 0 = zstd's default (3)
    pub zstd_level: i32,
    pub oodle_compressor: OodleCompressor,
    /// -4 (HyperFast4) … 9 (Optimal5); 4 = Normal
    pub oodle_level: i32,
}

impl Default for CompressionOptions {
    fn default() -> Self {
        CompressionOptions {
            zlib_level: 1,
            gzip_level: 1,
            zstd_level: 0,
            oodle_compressor: OodleCompressor::Mermaid,
            oodle_level: 4,
        }
    }
}

/// repak's historical default: the largest block size that fits the compact
/// encoding in the entry flags (readable by every engine version).
pub const DEFAULT_COMPRESSION_BLOCK_SIZE: u32 = 0x3e << 11;

pub(crate) fn build_partial_entry<D>(
    allowed_compression: &[Compression],
    compression_block_size: u32,
    options: &CompressionOptions,
    data: D,
) -> Result<PartialEntry<D>>
where
    D: AsRef<[u8]>,
{
    use sha1::{Digest, Sha1};

    // Empty data cannot be compressed (would produce empty blocks causing decompression failures)
    let compression = if data.as_ref().is_empty() {
        None
    } else {
        // TODO possibly select best compression based on some criteria instead of picking first
        allowed_compression.first().cloned()
    };
    let uncompressed_size = data.as_ref().len() as u64;

    #[cfg(feature = "compression")]
    if let Some(compression) = compression {
        // https://github.com/EpicGames/UnrealEngine/commit/3aad0ff7976be1073005dca2c1282af548b45d89
        // Block sizes above DEFAULT_COMPRESSION_BLOCK_SIZE need the extended
        // encoding, which older engine versions cannot read.
        let block_size = compression_block_size.max(1);
        let mut compressed_size = 0;
        let mut blocks = vec![];
        for chunk in data.as_ref().chunks(block_size as usize) {
            let data = compress(compression, options, chunk)?;
            compressed_size += data.len() as u64;
            blocks.push(PartialBlock {
                uncompressed_size: chunk.len(),
                data,
            })
        }
        // Like UnrealPak: keep the entry uncompressed if compression doesn't help.
        if compressed_size < uncompressed_size {
            let mut hasher = Sha1::new();
            for block in &blocks {
                hasher.update(&block.data);
            }
            return Ok(PartialEntry {
                compression: Some(compression),
                compressed_size,
                uncompressed_size,
                compression_block_size: block_size,
                data: PartialEntryData::Blocks(blocks),
                hash: Hash(hasher.finalize().into()),
            });
        }
    }
    #[cfg(not(feature = "compression"))]
    let _ = (compression, compression_block_size, options);

    Ok(PartialEntry {
        compression: None,
        compressed_size: uncompressed_size,
        uncompressed_size,
        compression_block_size: 0,
        hash: Hash(Sha1::digest(data.as_ref()).into()),
        data: PartialEntryData::Slice(data),
    })
}

#[cfg(feature = "compression")]
pub(crate) fn compress(compression: Compression, options: &CompressionOptions, data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;

    let compressed = match compression {
        Compression::Zlib => {
            let mut compress = flate2::write::ZlibEncoder::new(
                Vec::new(),
                flate2::Compression::new(options.zlib_level.min(9)),
            );
            compress.write_all(data.as_ref())?;
            compress.finish()?
        }
        Compression::Gzip => {
            let mut compress = flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::new(options.gzip_level.min(9)),
            );
            compress.write_all(data.as_ref())?;
            compress.finish()?
        }
        Compression::Zstd => zstd::stream::encode_all(data, options.zstd_level.clamp(0, 22))?,
        Compression::LZ4 => lz4_flex::block::compress(data),
        Compression::Oodle => {
            #[cfg(not(feature = "oodle_core"))]
            return Err(super::Error::Oodle);
            #[cfg(feature = "oodle_core")]
            {
                let compressor = match options.oodle_compressor {
                    OodleCompressor::Kraken => oodle_loader::Compressor::Kraken,
                    OodleCompressor::Mermaid => oodle_loader::Compressor::Mermaid,
                    OodleCompressor::Selkie => oodle_loader::Compressor::Selkie,
                    OodleCompressor::Leviathan => oodle_loader::Compressor::Leviathan,
                    OodleCompressor::Hydra => oodle_loader::Compressor::Hydra,
                };
                let level = oodle_loader::CompressionLevel::from_i32(options.oodle_level)
                    .unwrap_or(oodle_loader::CompressionLevel::Normal);
                oodle_loader::oodle()?.compress(data.as_ref(), compressor, level)?
            }
        }
    };

    Ok(compressed)
}
