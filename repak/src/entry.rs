use crate::{data::build_partial_entry, Error, Hash};

use super::{ext::BoolExt, ext::ReadExt, Compression, Version, VersionMajor};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::io;

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum EntryLocation {
    Data,
    Index,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Block {
    pub start: u64,
    pub end: u64,
}

impl Block {
    pub fn read<R: io::Read>(reader: &mut R) -> Result<Self, super::Error> {
        Ok(Self {
            start: reader.read_u64::<LE>()?,
            end: reader.read_u64::<LE>()?,
        })
    }

    pub fn write<W: io::Write>(&self, writer: &mut W) -> Result<(), super::Error> {
        writer.write_u64::<LE>(self.start)?;
        writer.write_u64::<LE>(self.end)?;
        Ok(())
    }
}

fn align(offset: u64) -> u64 {
    // add alignment (aes block size: 16) then zero out alignment bits
    (offset + 15) & !15
}

fn compression_index_size(version: Version) -> CompressionIndexSize {
    match version {
        Version::V8A => CompressionIndexSize::U8,
        _ => CompressionIndexSize::U32,
    }
}

enum CompressionIndexSize {
    U8,
    U32,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Entry {
    pub offset: u64,
    pub compressed: u64,
    pub uncompressed: u64,
    pub compression_slot: Option<u32>,
    pub timestamp: Option<u64>,
    pub hash: Option<Hash>,
    pub blocks: Option<Vec<Block>>,
    pub flags: u8,
    pub compression_block_size: u32,
}

impl Entry {
    pub fn is_encrypted(&self) -> bool {
        0 != (self.flags & 1)
    }
    pub fn is_deleted(&self) -> bool {
        0 != (self.flags >> 1) & 1
    }
    pub fn get_serialized_size(
        version: super::Version,
        compression: Option<u32>,
        block_count: u32,
    ) -> u64 {
        let mut size = 0;
        size += 8; // offset
        size += 8; // compressed
        size += 8; // uncompressed
        size += match compression_index_size(version) {
            CompressionIndexSize::U8 => 1,  // 8 bit compression
            CompressionIndexSize::U32 => 4, // 32 bit compression
        };
        size += match version.version_major() == VersionMajor::Initial {
            true => 8, // timestamp
            false => 0,
        };
        size += 20; // hash
        size += match compression {
            Some(_) => 4 + (8 + 8) * block_count as u64, // blocks
            None => 0,
        };
        size += 1; // encrypted
        size += match version.version_major() >= VersionMajor::CompressionEncryption {
            true => 4, // blocks uncompressed
            false => 0,
        };
        size
    }

    pub(crate) fn write_file<W: io::Write + io::Seek>(
        writer: &mut W,
        version: Version,
        compression_slots: &mut Vec<Option<Compression>>,
        allowed_compression: &[Compression],
        compression_block_size: u32,
        options: &crate::CompressionOptions,
        data: &[u8],
    ) -> Result<Self, Error> {
        let partial_entry =
            build_partial_entry(allowed_compression, compression_block_size, options, data)?;
        let stream_position = writer.stream_position()?;
        let entry = partial_entry.build_entry(version, compression_slots, stream_position)?;
        entry.write(writer, version, crate::entry::EntryLocation::Data)?;
        partial_entry.write_data(writer)?;
        Ok(entry)
    }

    /// Streams `size` bytes from `source` into a new entry at the writer's
    /// position, one compression block at a time. Output is byte-identical
    /// to [`Entry::write_file`] for the same data. `progress(bytes)` is called
    /// as data is consumed; returning `false` aborts with `Error::Cancelled`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn write_file_from_reader<W: io::Write + io::Seek, R: io::Read + io::Seek>(
        writer: &mut W,
        version: Version,
        compression_slots: &mut Vec<Option<Compression>>,
        allowed_compression: &[Compression],
        compression_block_size: u32,
        options: &crate::CompressionOptions,
        source: &mut R,
        size: u64,
        progress: &mut dyn FnMut(u64) -> bool,
    ) -> Result<Self, Error> {
        use sha1::{Digest, Sha1};
        let start = writer.stream_position()?;
        let source_start = source.stream_position()?;
        let compression = if size == 0 { None } else { allowed_compression.first().copied() };

        #[cfg(feature = "compression")]
        if let Some(comp) = compression {
            let block_size = compression_block_size.max(1) as u64;
            let n_blocks = size.div_ceil(block_size);
            // allocate the slot on a copy: committed only if compression is kept
            let mut slots = compression_slots.clone();
            let slot = crate::data::get_compression_slot(version, &mut slots, comp)?;
            let header = Entry::get_serialized_size(version, Some(slot), n_blocks as u32);
            writer.seek(io::SeekFrom::Start(start + header))?;
            let mut hasher = Sha1::new();
            let mut blocks = Vec::with_capacity(n_blocks.min(1 << 20) as usize);
            let mut offset = header;
            if version.version_major() < VersionMajor::RelativeChunkOffsets {
                offset += start;
            }
            let mut compressed_size = 0;
            let mut chunk = vec![0u8; block_size.min(size) as usize];
            let mut left = size;
            while left > 0 {
                let n = left.min(block_size) as usize;
                source.read_exact(&mut chunk[..n])?;
                let data = crate::data::compress(comp, options, &chunk[..n])?;
                writer.write_all(&data)?;
                hasher.update(&data);
                blocks.push(Block {
                    start: offset,
                    end: offset + data.len() as u64,
                });
                offset += data.len() as u64;
                compressed_size += data.len() as u64;
                left -= n as u64;
                if !progress(n as u64) {
                    return Err(Error::Cancelled);
                }
            }
            if compressed_size < size {
                *compression_slots = slots;
                let entry = Entry {
                    offset: start,
                    compressed: compressed_size,
                    uncompressed: size,
                    compression_slot: Some(slot),
                    timestamp: None,
                    hash: Some(Hash(hasher.finalize().into())),
                    blocks: Some(blocks),
                    flags: 0,
                    compression_block_size: block_size as u32,
                };
                writer.seek(io::SeekFrom::Start(start))?;
                entry.write(writer, version, EntryLocation::Data)?;
                writer.seek(io::SeekFrom::Start(start + header + compressed_size))?;
                return Ok(entry);
            }
            // didn't shrink: store it raw (second pass over the source)
            source.seek(io::SeekFrom::Start(source_start))?;
        }
        #[cfg(not(feature = "compression"))]
        let _ = (compression, compression_block_size, options);

        let header = Entry::get_serialized_size(version, None, 0);
        writer.seek(io::SeekFrom::Start(start + header))?;
        let mut hasher = Sha1::new();
        let mut chunk = vec![0u8; (1u64 << 20).min(size.max(1)) as usize];
        let mut left = size;
        let reported = compression.is_some();
        while left > 0 {
            let n = left.min(chunk.len() as u64) as usize;
            source.read_exact(&mut chunk[..n])?;
            writer.write_all(&chunk[..n])?;
            hasher.update(&chunk[..n]);
            left -= n as u64;
            // a raw second pass only checks for Cancel (bytes already reported)
            if !progress(if reported { 0 } else { n as u64 }) {
                return Err(Error::Cancelled);
            }
        }
        let entry = Entry {
            offset: start,
            compressed: size,
            uncompressed: size,
            compression_slot: None,
            timestamp: None,
            hash: Some(Hash(hasher.finalize().into())),
            blocks: None,
            flags: 0,
            compression_block_size: 0,
        };
        writer.seek(io::SeekFrom::Start(start))?;
        entry.write(writer, version, EntryLocation::Data)?;
        writer.seek(io::SeekFrom::Start(start + header + size))?;
        Ok(entry)
    }

    pub fn read<R: io::Read>(
        reader: &mut R,
        version: super::Version,
    ) -> Result<Self, super::Error> {
        let ver = version.version_major();
        let offset = reader.read_u64::<LE>()?;
        let compressed = reader.read_u64::<LE>()?;
        let uncompressed = reader.read_u64::<LE>()?;
        let compression = match match compression_index_size(version) {
            CompressionIndexSize::U8 => reader.read_u8()? as u32,
            CompressionIndexSize::U32 => reader.read_u32::<LE>()?,
        } {
            0 => None,
            n => Some(n - 1),
        };
        let timestamp = (ver == VersionMajor::Initial).then_try(|| reader.read_u64::<LE>())?;
        let hash = Some(Hash(reader.read_guid()?));
        let blocks = (ver >= VersionMajor::CompressionEncryption && compression.is_some())
            .then_try(|| reader.read_array(Block::read))?;
        let flags = (ver >= VersionMajor::CompressionEncryption)
            .then_try(|| reader.read_u8())?
            .unwrap_or(0);
        let compression_block_size = (ver >= VersionMajor::CompressionEncryption)
            .then_try(|| reader.read_u32::<LE>())?
            .unwrap_or(0);
        Ok(Self {
            offset,
            compressed,
            uncompressed,
            compression_slot: compression,
            timestamp,
            hash,
            blocks,
            flags,
            compression_block_size,
        })
    }

    pub fn write<W: io::Write>(
        &self,
        writer: &mut W,
        version: super::Version,
        location: EntryLocation,
    ) -> Result<(), super::Error> {
        writer.write_u64::<LE>(match location {
            EntryLocation::Data => 0,
            EntryLocation::Index => self.offset,
        })?;
        writer.write_u64::<LE>(self.compressed)?;
        writer.write_u64::<LE>(self.uncompressed)?;
        let compression = self.compression_slot.map_or(0, |n| n + 1);
        match compression_index_size(version) {
            CompressionIndexSize::U8 => writer.write_u8(compression.try_into().unwrap())?,
            CompressionIndexSize::U32 => writer.write_u32::<LE>(compression)?,
        }

        if version.version_major() == VersionMajor::Initial {
            writer.write_u64::<LE>(self.timestamp.unwrap_or_default())?;
        }
        if let Some(hash) = self.hash {
            writer.write_all(&hash.0)?;
        } else {
            panic!("hash missing");
        }
        if version.version_major() >= VersionMajor::CompressionEncryption {
            if let Some(blocks) = &self.blocks {
                writer.write_u32::<LE>(blocks.len() as u32)?;
                for block in blocks {
                    block.write(writer)?;
                }
            }
            writer.write_u8(self.flags)?;
            writer.write_u32::<LE>(self.compression_block_size)?;
        }

        Ok(())
    }

    pub fn read_encoded<R: io::Read>(
        reader: &mut R,
        version: super::Version,
    ) -> Result<Self, super::Error> {
        let bits = reader.read_u32::<LE>()?;
        let compression = match (bits >> 23) & 0x3f {
            0 => None,
            n => Some(n - 1),
        };

        let encrypted = (bits & (1 << 22)) != 0;
        let compression_block_count: u32 = (bits >> 6) & 0xffff;
        let mut compression_block_size = bits & 0x3f;

        if compression_block_size == 0x3f {
            compression_block_size = reader.read_u32::<LE>()?;
        } else {
            compression_block_size <<= 11;
        }

        let mut var_int = |bit: u32| -> Result<_, super::Error> {
            Ok(if (bits & (1 << bit)) != 0 {
                reader.read_u32::<LE>()? as u64
            } else {
                reader.read_u64::<LE>()?
            })
        };

        let offset = var_int(31)?;
        let uncompressed = var_int(30)?;
        let compressed = match compression {
            None => uncompressed,
            _ => var_int(29)?,
        };

        let offset_base = Entry::get_serialized_size(version, compression, compression_block_count);

        let blocks = if compression_block_count == 1 && !encrypted {
            Some(vec![Block {
                start: offset_base,
                end: offset_base + compressed,
            }])
        } else if compression_block_count > 0 {
            let mut index = offset_base;
            Some(
                (0..compression_block_count)
                    .map(|_| {
                        let mut block_size = reader.read_u32::<LE>()? as u64;
                        let block = Block {
                            start: index,
                            end: index + block_size,
                        };
                        if encrypted {
                            block_size = align(block_size);
                        }
                        index += block_size;
                        Ok(block)
                    })
                    .collect::<Result<Vec<_>, super::Error>>()?,
            )
        } else {
            None
        };

        Ok(Entry {
            offset,
            compressed,
            uncompressed,
            timestamp: None,
            compression_slot: compression,
            hash: None,
            blocks,
            flags: encrypted as u8,
            compression_block_size,
        })
    }

    pub fn write_encoded<W: io::Write>(&self, writer: &mut W) -> Result<(), super::Error> {
        let mut compression_block_size = (self.compression_block_size >> 11) & 0x3f;
        if (compression_block_size << 11) != self.compression_block_size {
            compression_block_size = 0x3f;
        }
        let compression_blocks_count = if self.compression_slot.is_some() {
            self.blocks.as_ref().unwrap().len() as u32
        } else {
            0
        };
        let is_size_32_bit_safe = self.compressed <= u32::MAX as u64;
        let is_uncompressed_size_32_bit_safe = self.uncompressed <= u32::MAX as u64;
        let is_offset_32_bit_safe = self.offset <= u32::MAX as u64;

        assert!(
            compression_blocks_count < 0x10_000,
            "compression blocks count fits in 16 bits"
        );

        let flags = (compression_block_size)
            | (compression_blocks_count << 6)
            | ((self.is_encrypted() as u32) << 22)
            | (self.compression_slot.map_or(0, |n| n + 1) << 23)
            | ((is_size_32_bit_safe as u32) << 29)
            | ((is_uncompressed_size_32_bit_safe as u32) << 30)
            | ((is_offset_32_bit_safe as u32) << 31);

        writer.write_u32::<LE>(flags)?;

        if compression_block_size == 0x3f {
            writer.write_u32::<LE>(self.compression_block_size)?;
        }

        if is_offset_32_bit_safe {
            writer.write_u32::<LE>(self.offset as u32)?;
        } else {
            writer.write_u64::<LE>(self.offset)?;
        }

        if is_uncompressed_size_32_bit_safe {
            writer.write_u32::<LE>(self.uncompressed as u32)?
        } else {
            writer.write_u64::<LE>(self.uncompressed)?
        }

        if self.compression_slot.is_some() {
            if is_size_32_bit_safe {
                writer.write_u32::<LE>(self.compressed as u32)?;
            } else {
                writer.write_u64::<LE>(self.compressed)?;
            }

            assert!(self.blocks.is_some());
            let blocks = self.blocks.as_ref().unwrap();
            if blocks.len() > 1 || self.is_encrypted() {
                for b in blocks {
                    let block_size = b.end - b.start;
                    writer.write_u32::<LE>(block_size.try_into().unwrap())?;
                }
            }
        }

        Ok(())
    }

    /// Streams an entry to `buf` block by block: memory use is one
    /// compression block (or 1 MiB for stored entries), whatever the entry
    /// size. With `verify`, the entry's SHA-1 (from the record stored before
    /// the data; v10+ index entries carry none) is checked
    /// (`Error::HashMismatch`). Verified against real Unreal paks: the hash
    /// covers the stored bytes; for encrypted compressed entries, the
    /// encrypted bytes including AES padding. Encrypted uncompressed entries
    /// are not checked (no reliable rule found).
    #[allow(clippy::too_many_arguments)]
    pub fn read_file<R: io::Read + io::Seek, W: io::Write>(
        &self,
        reader: &mut R,
        version: Version,
        compression: &[Option<Compression>],
        #[allow(unused)] key: &super::Key,
        buf: &mut W,
        verify: bool,
    ) -> Result<(), super::Error> {
        use sha1::{Digest, Sha1};
        reader.seek(io::SeekFrom::Start(self.offset))?;
        let header = Entry::read(reader, version)?;
        let data_offset = reader.stream_position()?;
        let encrypted = self.is_encrypted();
        let expected = header.hash.or(self.hash);
        #[cfg(feature = "encryption")]
        let cipher = match (encrypted, key) {
            (false, _) => None,
            (true, super::Key::Some(k)) => Some(k),
            (true, _) => return Err(super::Error::Encrypted),
        };
        #[cfg(not(feature = "encryption"))]
        if encrypted {
            return Err(super::Error::Encryption);
        }
        let stored_len = match encrypted {
            true => align(self.compressed),
            false => self.compressed,
        };
        let compressed_entry = self.compression_slot.is_some();
        // unencrypted: hash the bytes as read; encrypted+compressed: a
        // separate pass over the raw (encrypted) bytes below
        let mut hasher = (verify && !encrypted).then(Sha1::new);

        // Reads stored bytes [lo, hi) (relative to the data start), decrypting
        // whole AES blocks around the range (ECB: blocks are independent).
        {
        let mut span = |reader: &mut R, lo: u64, hi: u64| -> Result<Vec<u8>, super::Error> {
            let (lo16, hi16) = match encrypted {
                true => (lo & !15, align(hi).min(stored_len)),
                false => (lo, hi),
            };
            reader.seek(io::SeekFrom::Start(data_offset + lo16))?;
            #[allow(unused_mut)]
            let mut data = reader.read_len((hi16 - lo16) as usize)?;
            #[cfg(feature = "encryption")]
            if let Some(key) = cipher {
                use aes::cipher::BlockDecrypt;
                for block in data.chunks_mut(16) {
                    key.decrypt_block(aes::Block::from_mut_slice(block))
                }
            }
            let start = (lo - lo16) as usize;
            data.drain(..start);
            data.truncate((hi - lo) as usize);
            if let Some(h) = hasher.as_mut() {
                h.update(&data);
            }
            Ok(data)
        };

        const CHUNK: u64 = 1 << 20;
        match self.compression_slot.and_then(|c| compression[c as usize]) {
            None => {
                let mut pos = 0;
                while pos < self.compressed {
                    let end = (pos + CHUNK).min(self.compressed);
                    buf.write_all(&span(reader, pos, end)?)?;
                    pos = end;
                }
            }
            #[cfg(not(feature = "compression"))]
            _ => return Err(super::Error::Compression),
            #[cfg(feature = "compression")]
            Some(comp) => {
                let rel = |index: u64| -> u64 {
                    match version.version_major() >= VersionMajor::RelativeChunkOffsets {
                        true => index - (data_offset - self.offset),
                        false => index - data_offset,
                    }
                };
                let ranges: Vec<(u64, u64)> = match &self.blocks {
                    Some(blocks) => blocks.iter().map(|b| (rel(b.start), rel(b.end))).collect(),
                    None => vec![(0, self.compressed)],
                };
                let chunk_size = if ranges.len() == 1 {
                    self.uncompressed
                } else {
                    self.compression_block_size as u64
                };
                for (i, (lo, hi)) in ranges.iter().enumerate() {
                    let block = span(reader, *lo, *hi)?;
                    let out_len = chunk_size.min(self.uncompressed - (i as u64 * chunk_size).min(self.uncompressed));
                    match comp {
                        Compression::Zlib => {
                            io::copy(&mut flate2::read::ZlibDecoder::new(&block[..]), buf)?;
                        }
                        Compression::Gzip => {
                            io::copy(&mut flate2::read::GzDecoder::new(&block[..]), buf)?;
                        }
                        Compression::Zstd => {
                            io::copy(&mut zstd::stream::read::Decoder::new(&block[..])?, buf)?;
                        }
                        Compression::LZ4 => {
                            let mut out = vec![0; out_len as usize];
                            lz4_flex::block::decompress_into(&block, &mut out)
                                .map_err(|_| Error::DecompressionFailed(Compression::LZ4))?;
                            buf.write_all(&out)?;
                        }
                        #[cfg(feature = "oodle_core")]
                        Compression::Oodle => {
                            let mut out = vec![0; out_len as usize];
                            if oodle_loader::oodle()?.decompress(&block, &mut out) == 0 {
                                return Err(Error::DecompressionFailed(Compression::Oodle));
                            }
                            buf.write_all(&out)?;
                        }
                        #[cfg(not(feature = "oodle_core"))]
                        Compression::Oodle => return Err(super::Error::Oodle),
                    }
                }
            }
        }
        }
        buf.flush()?;
        if verify && encrypted && compressed_entry {
            let mut h = Sha1::new();
            reader.seek(io::SeekFrom::Start(data_offset))?;
            let mut left = stored_len;
            let mut chunk = vec![0u8; (1 << 20).min(stored_len.max(1)) as usize];
            while left > 0 {
                let n = left.min(chunk.len() as u64) as usize;
                reader.read_exact(&mut chunk[..n])?;
                h.update(&chunk[..n]);
                left -= n as u64;
            }
            hasher = Some(h);
        }
        if let (Some(h), Some(expected)) = (hasher, expected) {
            let actual: [u8; 20] = h.finalize().into();
            if actual != expected.0 {
                return Err(super::Error::HashMismatch);
            }
        }
        Ok(())
    }
}

mod test {
    #[test]
    fn test_entry() {
        let data = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xDD, 0x94, 0xFD, 0xC3, 0x5F, 0xF5, 0x91, 0xA9, 0x9A, 0x5E, 0x14, 0xDC, 0x9B,
            0xD3, 0x58, 0x89, 0x78, 0xA6, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut out = vec![];
        let entry = super::Entry::read(&mut std::io::Cursor::new(data.clone()), super::Version::V5)
            .unwrap();
        entry
            .write(&mut out, super::Version::V5, super::EntryLocation::Data)
            .unwrap();
        assert_eq!(&data, &out);
    }
}
