#![cfg(feature = "default")]
use byteorder::{ReadBytesExt, WriteBytesExt};
use paste::paste;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

/// A reader that tracks how many times bytes in the inner reader been read. Useful to check read coverage.
#[derive(Debug)]
pub struct ReadCounter<T> {
    inner: T,
    reads: io::Cursor<Vec<u8>>,
}

impl<T> ReadCounter<T> {
    pub fn new(inner: T) -> Self {
        ReadCounter {
            inner,
            reads: Cursor::new(vec![]),
        }
    }
    pub fn new_size(inner: T, size: usize) -> Self {
        ReadCounter {
            inner,
            reads: Cursor::new(vec![0; size]),
        }
    }
    pub fn into_reads(self) -> Vec<u8> {
        self.reads.into_inner()
    }
}

impl<T> Seek for ReadCounter<T>
where
    T: Seek,
{
    fn seek(&mut self, style: SeekFrom) -> io::Result<u64> {
        self.reads.seek(style).unwrap();
        self.inner.seek(style)
    }
}

impl<T> Read for ReadCounter<T>
where
    T: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf);
        if let Ok(read) = read {
            for _ in 0..read {
                let save = self.reads.position();
                let r = match self.reads.read_u8() {
                    Ok(r) => {
                        self.reads.seek(SeekFrom::Current(-1)).unwrap();
                        Ok(r)
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        // since rust 1.80 read_exact will move cursor position to end of internal
                        // buffer so we have to reset it
                        // ref https://github.com/rust-lang-ci/rust/commit/67b37f5054e4508694b7bd0b766e27f64cbd2d7f
                        self.reads.seek(SeekFrom::Start(save)).unwrap();
                        Ok(0)
                    }
                    Err(e) => Err(e),
                }
                .unwrap();
                self.reads.write_u8(r + 1).unwrap();
            }
        }
        read
    }
}

mod test {
    #[test]
    fn test_read_counter() {
        use byteorder::{ReadBytesExt, LE};
        use std::io::{Cursor, Seek, SeekFrom};

        let source = Cursor::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut proxy = super::ReadCounter::new(source);

        proxy.seek(SeekFrom::Start(3)).unwrap();
        proxy.read_u8().unwrap();
        proxy.seek(SeekFrom::Current(-1)).unwrap();
        proxy.read_u8().unwrap();
        proxy.read_u16::<LE>().unwrap();

        assert_eq!(proxy.reads.into_inner(), vec![0, 0, 0, 2, 1, 1]);
    }
}

static AES_KEY: &str = "lNJbw660IOC+kU7cnVQ1oeqrXyhk4J6UAZrCBbcnp94=";

fn test_read(version: repak::Version, _file_name: &str, bytes: &[u8]) {
    use aes::cipher::KeyInit;
    use base64::{engine::general_purpose, Engine as _};
    let key = general_purpose::STANDARD
        .decode(AES_KEY)
        .as_ref()
        .map_err(|_| repak::Error::Aes)
        .and_then(|bytes| aes::Aes256::new_from_slice(bytes).map_err(|_| repak::Error::Aes))
        .unwrap();

    let mut inner_reader = std::io::Cursor::new(bytes);
    let len = inner_reader.seek(SeekFrom::End(0)).unwrap();
    let mut reader = ReadCounter::new_size(inner_reader, len as usize);

    let pak = repak::PakBuilder::new()
        .key(key)
        .reader(&mut reader)
        .unwrap();

    assert_eq!(pak.mount_point(), "../mount/point/root/");
    assert_eq!(pak.version(), version);
    use std::collections::HashSet;
    let files: HashSet<String> = HashSet::from_iter(pak.files());
    assert_eq!(
        files,
        pak.entries()
            .map(|(p, _)| p.to_string())
            .collect::<HashSet<_>>()
    );
    assert_eq!(
        files,
        HashSet::from_iter(
            vec!["test.txt", "test.png", "zeros.bin", "directory/nested.txt"]
                .into_iter()
                .map(String::from)
        )
    );

    for file in files {
        let mut buf = vec![];
        let mut writer = std::io::Cursor::new(&mut buf);
        pak.read_file(&file, &mut reader, &mut writer).unwrap();
        let info = pak.entry(&file).expect("entry metadata");
        assert_eq!(
            info.uncompressed_size,
            buf.len() as u64,
            "{file} uncompressed size"
        );
        match file.as_str() {
            "test.txt" => assert_eq!(
                buf,
                include_bytes!("pack/root/test.txt"),
                "test.txt incorrect contents"
            ),
            "test.png" => assert_eq!(
                buf,
                include_bytes!("pack/root/test.png"),
                "test.png incorrect contents"
            ),
            "zeros.bin" => assert_eq!(
                buf,
                include_bytes!("pack/root/zeros.bin"),
                "zeros.bin incorrect contents"
            ),
            "directory/nested.txt" => assert_eq!(
                buf,
                include_bytes!("pack/root/directory/nested.txt"),
                "nested.txt incorrect contents"
            ),
            name => panic!("unrecognized file {}", name),
        }
    }

    for r in reader.into_reads() {
        // sanity check. a pak file can be constructed with a lot of dead space
        // which wouldn't have to be read, but so far all bytes in paks generated
        // by UnrealPak are meaningful
        assert!(r > 0, "every byte has been read at least once");
    }
}

fn test_write(_version: repak::Version, _file_name: &str, bytes: &[u8]) {
    use aes::cipher::KeyInit;
    use base64::{engine::general_purpose, Engine as _};
    let key = general_purpose::STANDARD
        .decode(AES_KEY)
        .as_ref()
        .map_err(|_| repak::Error::Aes)
        .and_then(|bytes| aes::Aes256::new_from_slice(bytes).map_err(|_| repak::Error::Aes))
        .unwrap();

    let mut reader = std::io::Cursor::new(bytes);
    let pak_reader = repak::PakBuilder::new()
        .key(key.clone())
        .reader(&mut reader)
        .unwrap();

    let writer = Cursor::new(vec![]);
    let mut pak_writer = repak::PakBuilder::new().key(key.clone()).writer(
        writer,
        pak_reader.version(),
        pak_reader.mount_point().to_owned(),
        pak_reader.path_hash_seed().or(Some(0x205C5A7D)),
    );
    // encryption as in the source pak (UnrealPak-made): the rewrite must be
    // byte-identical, padding and entry hashes included
    pak_writer.set_encrypt_entries(pak_reader.entries().any(|(_, e)| e.encrypted));
    pak_writer.set_encrypt_index(pak_reader.encrypted_index());
    pak_writer.set_encryption_guid(pak_reader.encryption_guid());

    for path in pak_reader.files() {
        let data = pak_reader.get(&path, &mut reader).unwrap();
        pak_writer.write_file(&path, false, data).unwrap();
    }

    let ours = pak_writer.write_index().unwrap().into_inner();
    let theirs = reader.into_inner();
    if _file_name.starts_with("pack_v5_") && pak_reader.entries().any(|(_, e)| e.encrypted) {
        // the UnrealPak that made the v5 packs filled AES padding with
        // arbitrary bytes (newer ones repeat the data's start, which we do):
        // same layout, and the contents must read back the same
        assert_eq!(ours.len(), theirs.len());
        let mut r = Cursor::new(&ours);
        let p = repak::PakBuilder::new().key(key).reader(&mut r).unwrap();
        let mut t = Cursor::new(&theirs);
        for path in pak_reader.files() {
            assert_eq!(
                p.get(&path, &mut r).unwrap(),
                pak_reader.get(&path, &mut t).unwrap()
            );
        }
        return;
    }
    assert!(ours == theirs);
}

fn test_rewrite_index(_version: repak::Version, _file_name: &str, bytes: &[u8]) {
    use aes::cipher::KeyInit;
    use base64::{engine::general_purpose, Engine as _};
    let key = general_purpose::STANDARD
        .decode(AES_KEY)
        .as_ref()
        .map_err(|_| repak::Error::Aes)
        .and_then(|bytes| aes::Aes256::new_from_slice(bytes).map_err(|_| repak::Error::Aes))
        .unwrap();

    let mut buf = std::io::Cursor::new(bytes.to_vec());
    let pak_reader = repak::PakBuilder::new().key(key).reader(&mut buf).unwrap();

    let rewrite = pak_reader
        .into_pakwriter(buf)
        .unwrap()
        .write_index()
        .unwrap()
        .into_inner();

    assert!(bytes == rewrite);
}

macro_rules! matrix_test {
    ( $name:literal, ($($version:literal $exp_version:expr),* $(,)?), $compress:tt, $encrypt:tt, $encryptindex:tt, $body:tt ) => {
        $( matrix_test_compress!($name, $version, $exp_version, $compress, $encrypt, $encryptindex, $body); )*
    };
}

macro_rules! matrix_test_compress {
    ( $name:literal, $version:literal, $exp_version:expr, ($($compress:literal),* $(,)?), $encrypt:tt, $encryptindex:tt, $body:tt ) => {
        $( matrix_test_encrypt!($name, $version, $exp_version, $compress, $encrypt, $encryptindex, $body); )*
    };
}

macro_rules! matrix_test_encrypt {
    ( $name:literal, $version:literal, $exp_version:expr, $compress:literal, ($($encrypt:literal),* $(,)?), $encryptindex:tt, $body:tt ) => {
        $( matrix_test_encryptindex!($name, $version, $exp_version, $compress, $encrypt, $encryptindex, $body); )*
    };
}

macro_rules! matrix_test_encryptindex {
    ( $name:literal, $version:literal, $exp_version:expr, $compress:literal, $encrypt:literal, ($($encryptindex:literal),* $(,)?), $body:tt ) => {
        $( matrix_test_body!($name, $version, $exp_version, $compress, $encrypt, $encryptindex, $body); )*
    };
}

macro_rules! matrix_test_body {
    ( $name:literal, $version:literal, $exp_version:expr, $compress:literal, $encrypt:literal, $encryptindex:literal, $body:expr ) => {
        paste! {
            #[test]
            fn [< test_ $name _version_ $version $compress $encrypt $encryptindex >]() {
                $body(
                    $exp_version,
                    concat!("pack_", $version, $compress, $encrypt, $encryptindex, ".pak"),
                    include_bytes!(concat!("packs/pack_", $version, $compress, $encrypt, $encryptindex, ".pak")));
            }
        }
    };
}

matrix_test!(
    "read",
    (
        "v5" repak::Version::V5,
        "v7" repak::Version::V7,
        "v8a" repak::Version::V8A,
        "v8b" repak::Version::V8B,
        "v9" repak::Version::V9,
        "v11" repak::Version::V11,
    ),
    ("", "_compress"),
    ("", "_encrypt"),
    ("", "_encryptindex"),
    test_read
);

matrix_test!(
    "write",
    (
        "v5" repak::Version::V5,
        "v7" repak::Version::V7,
        "v8a" repak::Version::V8A,
        "v8b" repak::Version::V8B,
        "v9" repak::Version::V9,
        "v11" repak::Version::V11,
    ),
    ("", /*"_compress"*/),
    ("", "_encrypt"),
    ("", "_encryptindex"),
    test_write
);

matrix_test!(
    "rewrite_index",
    (
        "v5" repak::Version::V5,
        "v7" repak::Version::V7,
        "v8a" repak::Version::V8A,
        "v8b" repak::Version::V8B,
        "v9" repak::Version::V9,
        "v11" repak::Version::V11,
    ),
    ("", "_compress"),
    ("", "_encrypt"),
    ("", "_encryptindex"),
    test_rewrite_index
);

mod roundtrip {
    use std::io::Cursor;

    const FILE_CONTENTS: &[(&str, &[u8])] = &[
        ("hello.txt", b"Hello, world!"),
        ("empty.txt", b""),
        ("large.bin", &[0xAB; 4096]),
        ("dir/nested.txt", b"nested file content"),
    ];

    fn roundtrip(version: repak::Version, compression: Option<repak::Compression>) {
        let allowed_compression: Vec<repak::Compression> = compression.into_iter().collect();

        let writer = Cursor::new(vec![]);
        let mut builder = repak::PakBuilder::new();
        if !allowed_compression.is_empty() {
            builder = builder.compression(allowed_compression);
        }
        let mut pak_writer = builder.writer(writer, version, "../../../".to_string(), Some(0));

        for (path, data) in FILE_CONTENTS {
            pak_writer
                .write_file(path, compression.is_some(), *data)
                .unwrap();
        }

        let buf = pak_writer.write_index().unwrap().into_inner();

        let mut reader = Cursor::new(&buf);
        let pak_reader = repak::PakBuilder::new().reader(&mut reader).unwrap();

        assert_eq!(pak_reader.version(), version);
        assert_eq!(pak_reader.mount_point(), "../../../");

        let mut files: Vec<String> = pak_reader.files();
        files.sort();
        let mut expected: Vec<String> = FILE_CONTENTS.iter().map(|(p, _)| p.to_string()).collect();
        expected.sort();
        assert_eq!(files, expected);

        for (path, expected_data) in FILE_CONTENTS {
            let data = pak_reader.get(path, &mut reader).unwrap();
            assert_eq!(
                data, *expected_data,
                "mismatched content for {} with version {:?} compression {:?}",
                path, version, compression,
            );
        }
    }

    macro_rules! roundtrip_tests {
        (pre_fname: $($version:ident),+ $(,)?) => {
            $(
                paste::paste! {
                    #[test]
                    fn [< roundtrip_ $version:lower _none >]() {
                        roundtrip(repak::Version::$version, None);
                    }

                    #[test]
                    fn [< roundtrip_ $version:lower _zlib >]() {
                        roundtrip(repak::Version::$version, Some(repak::Compression::Zlib));
                    }

                    #[test]
                    fn [< roundtrip_ $version:lower _gzip >]() {
                        roundtrip(repak::Version::$version, Some(repak::Compression::Gzip));
                    }
                }
            )+
        };
        (fname: $($version:ident),+ $(,)?) => {
            $(
                paste::paste! {
                    #[test]
                    fn [< roundtrip_ $version:lower _none >]() {
                        roundtrip(repak::Version::$version, None);
                    }

                    #[test]
                    fn [< roundtrip_ $version:lower _zlib >]() {
                        roundtrip(repak::Version::$version, Some(repak::Compression::Zlib));
                    }

                    #[test]
                    fn [< roundtrip_ $version:lower _gzip >]() {
                        roundtrip(repak::Version::$version, Some(repak::Compression::Gzip));
                    }

                    #[test]
                    fn [< roundtrip_ $version:lower _zstd >]() {
                        roundtrip(repak::Version::$version, Some(repak::Compression::Zstd));
                    }

                    #[test]
                    fn [< roundtrip_ $version:lower _lz4 >]() {
                        roundtrip(repak::Version::$version, Some(repak::Compression::LZ4));
                    }
                }
            )+
        };
    }

    roundtrip_tests!(pre_fname: V5, V7);
    roundtrip_tests!(fname: V8A, V8B, V9, V11, V12);
}

#[test]
fn unknown_future_version_is_rejected_not_misparsed() {
    // Write a v12 pak, then patch the footer version to 99.
    let mut buf = std::io::Cursor::new(vec![]);
    let mut w =
        repak::PakBuilder::new().writer(&mut buf, repak::Version::V12, "../../../".into(), None);
    w.write_file("a.txt", false, b"hello").unwrap();
    w.write_index().unwrap();
    let mut bytes = buf.into_inner();
    let magic = 0x5A6F12E1u32.to_le_bytes();
    let pos = bytes.windows(4).rposition(|w| w == magic).unwrap();
    assert_eq!(&bytes[pos + 4..pos + 8], &12u32.to_le_bytes());
    bytes[pos + 4..pos + 8].copy_from_slice(&99u32.to_le_bytes());
    let err = repak::PakBuilder::new()
        .reader(&mut std::io::Cursor::new(bytes))
        .unwrap_err();
    assert!(matches!(err, repak::Error::UnsupportedVersion(99)), "{err}");
}

#[test]
fn wrong_key_is_detected_before_parsing() {
    use aes::cipher::KeyInit;
    let bytes = include_bytes!("packs/pack_v11_encrypt_encryptindex.pak");
    let wrong = aes::Aes256::new_from_slice(&[0x11; 32]).unwrap();
    let err = repak::PakBuilder::new()
        .key(wrong)
        .reader(&mut std::io::Cursor::new(&bytes[..]))
        .unwrap_err();
    assert!(matches!(err, repak::Error::WrongKey), "{err}");
    let err = repak::PakBuilder::new()
        .reader(&mut std::io::Cursor::new(&bytes[..]))
        .unwrap_err();
    assert!(matches!(err, repak::Error::Encrypted), "{err}");
}

#[test]
fn garbage_index_location_is_rejected() {
    let mut buf = std::io::Cursor::new(vec![]);
    let mut w =
        repak::PakBuilder::new().writer(&mut buf, repak::Version::V11, "../../../".into(), None);
    w.write_file("a.txt", false, b"hello").unwrap();
    w.write_index().unwrap();
    let mut bytes = buf.into_inner();
    let magic = 0x5A6F12E1u32.to_le_bytes();
    let pos = bytes.windows(4).rposition(|w| w == magic).unwrap();
    // index size = u64::MAX / 2
    bytes[pos + 16..pos + 24].copy_from_slice(&(u64::MAX / 2).to_le_bytes());
    let err = repak::PakBuilder::new()
        .reader_with_version(&mut std::io::Cursor::new(bytes), repak::Version::V11)
        .unwrap_err();
    assert!(matches!(err, repak::Error::InvalidIndex(_)), "{err}");
}

#[test]
fn block_size_and_uncompressible_fallback() {
    let compressible = b"abcd".repeat(70_000); // 280,000 bytes
    let mut x: u64 = 0x9E3779B97F4A7C15;
    let random: Vec<u8> = (0..50_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    let mut buf = std::io::Cursor::new(vec![]);
    let mut w = repak::PakBuilder::new()
        .compression([repak::Compression::Zlib])
        .compression_block_size(65536)
        .writer(&mut buf, repak::Version::V11, "../../../".into(), None);
    w.write_file("c.bin", true, &compressible).unwrap();
    w.write_file("r.bin", true, &random).unwrap();
    w.write_index().unwrap();
    let bytes = buf.into_inner();
    let mut r = std::io::Cursor::new(&bytes);
    let pak = repak::PakBuilder::new().reader(&mut r).unwrap();
    let c = pak.entry("c.bin").unwrap();
    assert_eq!(c.compression, Some(repak::Compression::Zlib));
    assert!(c.compressed_size < c.uncompressed_size);
    let rnd = pak.entry("r.bin").unwrap();
    assert_eq!(
        rnd.compression, None,
        "stored when compression doesn't help"
    );
    assert_eq!(pak.get("c.bin", &mut r).unwrap(), compressible);
    assert_eq!(pak.get("r.bin", &mut r).unwrap(), random);
}

#[test]
fn modify_existing_pak_in_place() {
    use std::io::{Seek, Write};
    // original: zlib, two files
    let mut buf = std::io::Cursor::new(vec![]);
    let mut w = repak::PakBuilder::new()
        .compression([repak::Compression::Zlib])
        .writer(
            &mut buf,
            repak::Version::V11,
            "../../../Game/Content/".into(),
            Some(7),
        );
    w.write_file("a.txt", true, b"aaaa".repeat(1000)).unwrap();
    w.write_file("dir/b.txt", true, b"bbbb".repeat(1000))
        .unwrap();
    w.write_index().unwrap();
    let original = buf.into_inner();

    // reopen: remove a, replace b, add c with another method, re-root, new mount
    let mut file = std::io::Cursor::new(original.clone());
    let pak = repak::PakBuilder::new().reader(&mut file).unwrap();
    let index_offset = pak.index_offset().unwrap();
    let mut w = pak.into_pakwriter(&mut file).unwrap();
    assert!(w.remove("a.txt"));
    assert!(!w.remove("missing"));
    w.set_compression([repak::Compression::Gzip]);
    w.set_compression_options(repak::CompressionOptions {
        gzip_level: 9,
        ..Default::default()
    });
    w.write_file("dir/b.txt", true, b"BBBB".repeat(1000))
        .unwrap();
    w.write_file("c.txt", true, b"cccc".repeat(1000)).unwrap();
    w.rename_all(|p| format!("Content/{p}")).unwrap();
    w.set_mount_point("../../../Game/".into());
    assert_eq!(w.paths(), ["Content/c.txt", "Content/dir/b.txt"]);
    let out = w.write_index().unwrap();
    let end = out.stream_position().unwrap();
    out.get_mut().truncate(end as usize);
    out.flush().unwrap();
    let bytes = file.into_inner();
    assert!(
        bytes[..index_offset as usize] == original[..index_offset as usize],
        "old data untouched"
    );

    let mut r = std::io::Cursor::new(&bytes);
    let pak = repak::PakBuilder::new().reader(&mut r).unwrap();
    assert_eq!(pak.mount_point(), "../../../Game/");
    assert_eq!(pak.path_hash_seed(), Some(7), "seed kept");
    assert_eq!(pak.files(), ["Content/c.txt", "Content/dir/b.txt"]);
    assert_eq!(
        pak.get("Content/dir/b.txt", &mut r).unwrap(),
        b"BBBB".repeat(1000)
    );
    assert_eq!(
        pak.get("Content/c.txt", &mut r).unwrap(),
        b"cccc".repeat(1000)
    );
    let methods = pak.used_compression();
    assert!(methods.contains(&repak::Compression::Gzip));

    // delete-only rewrite: new index is smaller -> must truncate to stay valid
    let mut file = std::io::Cursor::new(bytes.clone());
    let pak = repak::PakBuilder::new().reader(&mut file).unwrap();
    let mut w = pak.into_pakwriter(&mut file).unwrap();
    w.remove("Content/c.txt");
    let out = w.write_index().unwrap();
    let end = out.stream_position().unwrap();
    out.get_mut().truncate(end as usize);
    let bytes2 = file.into_inner();
    assert!(bytes2.len() < bytes.len());
    let mut r = std::io::Cursor::new(&bytes2);
    let pak = repak::PakBuilder::new().reader(&mut r).unwrap();
    assert_eq!(pak.files(), ["Content/dir/b.txt"]);

    // rename collision is refused without changes
    let mut file = std::io::Cursor::new(bytes);
    let pak = repak::PakBuilder::new().reader(&mut file).unwrap();
    let mut w = pak.into_pakwriter(&mut file).unwrap();
    assert!(w.rename_all(|_| "same".into()).is_err());
    assert_eq!(w.paths().len(), 2);
}

#[test]
fn compression_levels_change_output() {
    let data = b"The quick brown fox jumps over the lazy dog. ".repeat(4000);
    let size = |opts: repak::CompressionOptions, c: repak::Compression| {
        let mut buf = std::io::Cursor::new(vec![]);
        let mut w = repak::PakBuilder::new()
            .compression([c])
            .compression_options(opts)
            .writer(&mut buf, repak::Version::V11, "../../../".into(), None);
        w.write_file("x", true, &data).unwrap();
        w.write_index().unwrap();
        let bytes = buf.into_inner();
        let mut r = std::io::Cursor::new(&bytes);
        let pak = repak::PakBuilder::new().reader(&mut r).unwrap();
        assert_eq!(pak.get("x", &mut r).unwrap(), data);
        pak.entry("x").unwrap().compressed_size
    };
    let d = repak::CompressionOptions::default();
    assert!(
        size(
            repak::CompressionOptions { zlib_level: 9, ..d },
            repak::Compression::Zlib
        ) <= size(d, repak::Compression::Zlib)
    );
    assert!(
        size(
            repak::CompressionOptions {
                zstd_level: 19,
                ..d
            },
            repak::Compression::Zstd
        ) <= size(
            repak::CompressionOptions { zstd_level: 1, ..d },
            repak::Compression::Zstd
        )
    );
}

#[test]
fn streaming_write_is_byte_identical() {
    use repak::{Compression::*, Version::*};
    let mut x: u64 = 0x1234_5678_9abc_def1;
    let noise: Vec<u8> = (0..70_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect();
    let payloads: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("one", vec![7]),
        ("block", b"ab".repeat(32768)),
        (
            "block_plus_one",
            b"ab".repeat(32768).into_iter().chain([1]).collect(),
        ),
        ("multi", b"hello world ".repeat(30_000)),
        ("noise", noise),
    ];
    let versions = [V3, V4, V5, V7, V8A, V8B, V9, V10, V11, V12];
    let methods: [Option<repak::Compression>; 6] = [
        None,
        Some(Zlib),
        Some(Gzip),
        Some(Zstd),
        Some(LZ4),
        Some(Oodle),
    ];
    let mut compared = 0;
    for v in versions {
        for m in methods {
            if m == Some(Oodle) {
                continue; // needs the library
            }
            if v < V8A && matches!(m, Some(Zstd) | Some(LZ4)) {
                continue;
            }
            let build = |streaming: bool| {
                let mut buf = std::io::Cursor::new(vec![]);
                let mut b = repak::PakBuilder::new().compression_block_size(65536);
                if let Some(m) = m {
                    b = b.compression([m]);
                }
                let mut w = b.writer(&mut buf, v, "../../../G/".into(), None);
                for (name, data) in &payloads {
                    if streaming {
                        let mut src = std::io::Cursor::new(data.clone());
                        w.write_file_from_reader(
                            name,
                            m.is_some(),
                            &mut src,
                            data.len() as u64,
                            &mut |_| true,
                        )
                        .unwrap();
                    } else {
                        w.write_file(name, m.is_some(), data).unwrap();
                    }
                }
                w.write_index().unwrap();
                buf.into_inner()
            };
            let (a, b) = (build(false), build(true));
            assert!(a == b, "{v} {m:?}: streaming output differs");
            // and it reads back, also with hash verification
            let mut r = std::io::Cursor::new(&b);
            let pak = repak::PakBuilder::new().reader(&mut r).unwrap();
            for (name, data) in &payloads {
                let mut out = vec![];
                pak.read_file_verified(name, &mut r, &mut out).unwrap();
                assert_eq!(&out, data, "{v} {m:?} {name}");
            }
            compared += 1;
        }
    }
    assert_eq!(
        compared, 42,
        "10 versions x 5 methods, minus Zstd/LZ4 before V8A"
    );
}

#[test]
fn streaming_write_cancel_and_progress() {
    let data = b"xyz".repeat(100_000);
    let mut buf = std::io::Cursor::new(vec![]);
    let mut w = repak::PakBuilder::new()
        .compression([repak::Compression::Zlib])
        .compression_block_size(65536)
        .writer(&mut buf, repak::Version::V11, "../../../".into(), None);
    let mut seen = 0u64;
    let mut calls = 0;
    w.write_file_from_reader(
        "a",
        true,
        &mut std::io::Cursor::new(&data),
        data.len() as u64,
        &mut |n| {
            seen += n;
            calls += 1;
            true
        },
    )
    .unwrap();
    assert_eq!(seen, data.len() as u64);
    assert_eq!(calls, 5, "one call per 64 KB block");
    let err = w
        .write_file_from_reader(
            "b",
            true,
            &mut std::io::Cursor::new(&data),
            data.len() as u64,
            &mut |_| false,
        )
        .unwrap_err();
    assert!(matches!(err, repak::Error::Cancelled));
}

#[test]
fn verified_read_detects_corruption() {
    let mut buf = std::io::Cursor::new(vec![]);
    let mut w = repak::PakBuilder::new()
        .compression([repak::Compression::Zlib])
        .writer(&mut buf, repak::Version::V11, "../../../".into(), None);
    w.write_file("raw", false, b"raw data here").unwrap();
    w.write_index().unwrap();
    let mut bytes = buf.into_inner();
    let pos = bytes
        .windows(13)
        .position(|w| w == b"raw data here")
        .unwrap();
    bytes[pos] ^= 1;
    let mut r = std::io::Cursor::new(&bytes);
    let pak = repak::PakBuilder::new().reader(&mut r).unwrap();
    assert!(pak.get("raw", &mut r).is_ok(), "plain read doesn't verify");
    let err = pak
        .read_file_verified("raw", &mut r, &mut std::io::sink())
        .unwrap_err();
    assert!(matches!(err, repak::Error::HashMismatch));
}

/// A >4 GB entry through the streaming writer, without the data in memory.
#[test]
fn streaming_entry_over_4gb() {
    struct Zeros(u64, u64); // (pos, len)
    impl std::io::Read for Zeros {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (buf.len() as u64).min(self.1 - self.0) as usize;
            buf[..n].fill(0);
            self.0 += n as u64;
            Ok(n)
        }
    }
    impl std::io::Seek for Zeros {
        fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
            if let std::io::SeekFrom::Start(s) = p {
                self.0 = s;
            }
            Ok(self.0)
        }
    }
    /// Discards data, keeps the first 64 KB (headers) and tracks position.
    struct Sink(Vec<u8>, u64, u64);
    impl std::io::Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            for (i, byte) in b.iter().enumerate() {
                let at = self.1 + i as u64;
                if at < self.0.len() as u64 {
                    self.0[at as usize] = *byte;
                }
            }
            self.1 += b.len() as u64;
            self.2 = self.2.max(self.1);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl std::io::Seek for Sink {
        fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
            match p {
                std::io::SeekFrom::Start(s) => self.1 = s,
                std::io::SeekFrom::End(e) => self.1 = (self.2 as i64 + e) as u64,
                std::io::SeekFrom::Current(c) => self.1 = (self.1 as i64 + c) as u64,
            }
            Ok(self.1)
        }
    }
    let size = 4_300_000_000u64;
    let mut sink = Sink(vec![0; 65536], 0, 0);
    let mut w =
        repak::PakBuilder::new().writer(&mut sink, repak::Version::V11, "../../../".into(), None);
    w.write_file_from_reader("big.bin", false, &mut Zeros(0, size), size, &mut |_| true)
        .unwrap();
    w.write_index().unwrap();
    // in-data record: offset(0), compressed, uncompressed as u64
    let compressed = u64::from_le_bytes(sink.0[8..16].try_into().unwrap());
    let uncompressed = u64::from_le_bytes(sink.0[16..24].try_into().unwrap());
    assert_eq!((compressed, uncompressed), (size, size));
    assert!(sink.2 > size);
}

#[test]
fn data_end_and_write_at_reuse_tail() {
    for (v, comp) in [
        (repak::Version::V11, Some(repak::Compression::Zlib)),
        (repak::Version::V11, None),
        (repak::Version::V4, Some(repak::Compression::Zlib)),
        (repak::Version::V3, None),
    ] {
        let mut buf = std::io::Cursor::new(vec![]);
        let mut b = repak::PakBuilder::new();
        if let Some(c) = comp {
            b = b.compression([c]);
        }
        let mut w = b.writer(&mut buf, v, "../../../".into(), None);
        w.write_file("a", true, b"aaaa".repeat(5000)).unwrap();
        w.write_file("b", true, b"bbbb".repeat(5000)).unwrap();
        w.write_index().unwrap();
        let bytes = buf.into_inner();
        let mut r = std::io::Cursor::new(&bytes);
        let pak = repak::PakBuilder::new().reader(&mut r).unwrap();
        let a = pak.entry("a").unwrap();
        let bb = pak.entry("b").unwrap();
        assert_eq!(a.data_end, bb.offset, "{v} {comp:?}: a ends where b starts");
        assert_eq!(
            bb.data_end,
            pak.index_offset().unwrap(),
            "{v} {comp:?}: b ends at the index"
        );
        // replace b reusing its space: write at b.offset
        let mut file = std::io::Cursor::new(bytes.clone());
        let pak = repak::PakBuilder::new().reader(&mut file).unwrap();
        let at = pak.entry("b").unwrap().offset;
        let mut w = pak.into_pakwriter_at(&mut file, at).unwrap();
        w.remove("b");
        // a reopened writer defaults to the pak's slots (pre-v8: Zlib first)
        w.set_compression(comp);
        w.write_file("b", true, b"BBBB".repeat(5000)).unwrap();
        let out = w.write_index().unwrap();
        use std::io::Seek;
        let end = out.stream_position().unwrap();
        out.get_mut().truncate(end as usize);
        let new = file.into_inner();
        assert_eq!(
            new.len(),
            bytes.len(),
            "{v} {comp:?}: no growth when replacing the last entry"
        );
        let mut r = std::io::Cursor::new(&new);
        let pak = repak::PakBuilder::new().reader(&mut r).unwrap();
        assert_eq!(pak.get("b", &mut r).unwrap(), b"BBBB".repeat(5000));
        assert_eq!(pak.get("a", &mut r).unwrap(), b"aaaa".repeat(5000));
    }
    // encrypted test pak: data_end accounts for AES padding
    let bytes = include_bytes!("packs/pack_v8b_compress_encrypt.pak");
    use aes::cipher::KeyInit;
    let key = aes::Aes256::new_from_slice(
        &base64::Engine::decode(&base64::engine::general_purpose::STANDARD, AES_KEY).unwrap(),
    )
    .unwrap();
    let mut r = std::io::Cursor::new(&bytes[..]);
    let pak = repak::PakBuilder::new().key(key).reader(&mut r).unwrap();
    let mut spans: Vec<(u64, u64)> = pak.entries().map(|(_, e)| (e.offset, e.data_end)).collect();
    spans.sort();
    for w in spans.windows(2) {
        assert!(w[0].1 <= w[1].0, "entries don't overlap: {spans:?}");
    }
    assert!(spans.last().unwrap().1 <= pak.index_offset().unwrap());
}

#[test]
fn encrypted_write_roundtrip() {
    use aes::cipher::KeyInit;
    use repak::{Compression::*, Version::*};
    let key = aes::Aes256::new_from_slice(&[0x5a; 32]).unwrap();
    let wrong = aes::Aes256::new_from_slice(&[0x11; 32]).unwrap();
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let noise: Vec<u8> = (0..70_001)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect();
    let payloads: Vec<(&str, Vec<u8>)> = vec![
        ("a/empty", vec![]),
        ("a/one", vec![7]),
        ("a/fifteen", vec![3; 15]),
        ("a/sixteen", vec![4; 16]),
        ("b/text", b"hello world ".repeat(30_000)),
        ("b/noise", noise),
        ("c/big", b"0123456789abcdef!".repeat(80_000)), // > 1 MiB stored chunk
    ];
    let mut checked = 0;
    for v in [V4, V5, V7, V8A, V8B, V9, V10, V11, V12] {
        for m in [None, Some(Zlib), Some(Gzip), Some(Zstd), Some(LZ4)] {
            if v < V8A && matches!(m, Some(Zstd) | Some(LZ4)) {
                continue;
            }
            for streaming in [false, true] {
                let mut b = repak::PakBuilder::new()
                    .key(key.clone())
                    .compression_block_size(65536);
                if let Some(m) = m {
                    b = b.compression([m]);
                }
                let mut w = b.writer(Cursor::new(vec![]), v, "../../../G/".into(), Some(0x1234));
                w.set_encrypt_entries(true);
                w.set_encrypt_index(true);
                let guid = (v >= V7).then_some(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10u128);
                w.set_encryption_guid(guid);
                for (name, data) in &payloads {
                    if streaming {
                        let mut src = Cursor::new(data.clone());
                        w.write_file_from_reader(
                            name,
                            m.is_some(),
                            &mut src,
                            data.len() as u64,
                            &mut |_| true,
                        )
                        .unwrap();
                    } else {
                        w.write_file(name, m.is_some(), data).unwrap();
                    }
                }
                let bytes = w.write_index().unwrap().into_inner();
                let what = format!("{v:?} {m:?} streaming={streaming}");
                // no key / wrong key
                assert!(
                    matches!(
                        repak::PakBuilder::new().reader(&mut Cursor::new(&bytes)),
                        Err(repak::Error::Encrypted)
                    ),
                    "{what}"
                );
                assert!(
                    matches!(
                        repak::PakBuilder::new()
                            .key(wrong.clone())
                            .reader(&mut Cursor::new(&bytes)),
                        Err(repak::Error::WrongKey)
                    ),
                    "{what}"
                );
                let mut r = Cursor::new(&bytes);
                let pak = repak::PakBuilder::new()
                    .key(key.clone())
                    .reader(&mut r)
                    .unwrap();
                assert!(pak.encrypted_index(), "{what}");
                if v >= V7 {
                    assert_eq!(pak.encryption_guid(), guid, "{what}");
                }
                for (name, data) in &payloads {
                    let info = pak.entries().find(|(p, _)| p == name).unwrap().1;
                    assert_eq!(info.encrypted, !data.is_empty(), "{what} {name}");
                    let mut out = vec![];
                    pak.read_file_verified(name, &mut r, &mut out)
                        .unwrap_or_else(|e| panic!("{what} {name}: {e}"));
                    assert_eq!(&out, data, "{what} {name}");
                }
                // entries don't overlap and end before the index
                let mut spans: Vec<(u64, u64)> =
                    pak.entries().map(|(_, e)| (e.offset, e.data_end)).collect();
                spans.sort();
                for p in spans.windows(2) {
                    assert!(p[0].1 <= p[1].0, "{what}: {spans:?}");
                }
                assert!(
                    spans.last().unwrap().1 <= pak.index_offset().unwrap(),
                    "{what}"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 78);
}

#[test]
fn encrypted_append_keeps_index_encryption() {
    use aes::cipher::KeyInit;
    let key = aes::Aes256::new_from_slice(
        &base64::Engine::decode(&base64::engine::general_purpose::STANDARD, AES_KEY).unwrap(),
    )
    .unwrap();
    for bytes in [
        &include_bytes!("packs/pack_v11_compress_encrypt_encryptindex.pak")[..],
        &include_bytes!("packs/pack_v8b_encrypt_encryptindex.pak")[..],
        &include_bytes!("packs/pack_v11_encryptindex.pak")[..],
    ] {
        let mut buf = Cursor::new(bytes.to_vec());
        let pak = repak::PakBuilder::new()
            .key(key.clone())
            .reader(&mut buf)
            .unwrap();
        let encrypt_entries = pak.entries().any(|(_, e)| e.encrypted);
        let at = pak.index_offset().unwrap();
        let old: Vec<String> = pak.files();
        let mut w = pak.into_pakwriter_at(buf, at).unwrap();
        w.set_compression([repak::Compression::Zlib]);
        w.set_encrypt_entries(encrypt_entries);
        w.write_file("new/added.txt", true, b"added ".repeat(5000))
            .unwrap();
        let mut out = w.write_index().unwrap();
        let end = out.stream_position().unwrap();
        out.get_mut().truncate(end as usize);
        let new = out.into_inner();
        assert!(matches!(
            repak::PakBuilder::new().reader(&mut Cursor::new(&new)),
            Err(repak::Error::Encrypted)
        ));
        let mut r = Cursor::new(&new);
        let p = repak::PakBuilder::new()
            .key(key.clone())
            .reader(&mut r)
            .unwrap();
        assert!(p.encrypted_index());
        let added = p.entries().find(|(n, _)| *n == "new/added.txt").unwrap().1;
        assert_eq!(added.encrypted, encrypt_entries);
        let mut data = vec![];
        p.read_file_verified("new/added.txt", &mut r, &mut data)
            .unwrap();
        assert_eq!(data, b"added ".repeat(5000));
        for f in old {
            p.read_file_verified(&f, &mut r, &mut std::io::sink())
                .unwrap();
        }
    }
}

/// With `UEPAK_KEYED_PAK` / `UEPAK_KEYED_KEY` (a real encrypted pak and its
/// key, kept out of the repo): rewriting its index keeps it readable with
/// the same key, same entries and same footer. (Not byte-identical: UE
/// writes the full directory index in hash-map order; same contents.)
#[test]
fn real_encrypted_pak_index_rewrite_reads_back() {
    let (Ok(path), Ok(hex)) = (
        std::env::var("UEPAK_KEYED_PAK"),
        std::env::var("UEPAK_KEYED_KEY"),
    ) else {
        return;
    };
    use aes::cipher::KeyInit;
    let hex = hex.trim_start_matches("0x");
    let raw: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    let key = aes::Aes256::new_from_slice(&raw).unwrap();
    let bytes = std::fs::read(path).unwrap();
    let mut buf = Cursor::new(bytes.clone());
    let pak = repak::PakBuilder::new()
        .key(key.clone())
        .reader(&mut buf)
        .unwrap();
    assert!(pak.encrypted_index());
    let before: Vec<_> = pak.entries().map(|(p, e)| (p.to_string(), e)).collect();
    let (guid, at) = (pak.encryption_guid(), pak.index_offset().unwrap());
    let out = pak
        .into_pakwriter_at(buf, at)
        .unwrap()
        .write_index()
        .unwrap()
        .into_inner();
    assert_eq!(out.len(), bytes.len());
    assert_eq!(out[..at as usize], bytes[..at as usize]);
    // v11 footer: GUID 16, encrypted 1, magic 4, version 4, offset 8, size 8,
    // hash 20 (differs with the directory order), compression names 160
    let foot = |b: &[u8]| {
        let f = &b[b.len() - 221..];
        [&f[..41], &f[61..]].concat()
    };
    assert_eq!(foot(&out), foot(&bytes), "footer except the index hash");
    let mut r = Cursor::new(&out);
    let p = repak::PakBuilder::new().key(key).reader(&mut r).unwrap();
    assert_eq!(p.encryption_guid(), guid);
    let after: Vec<_> = p.entries().map(|(p, e)| (p.to_string(), e)).collect();
    assert_eq!(before, after);
}
