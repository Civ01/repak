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
        pak.entries().map(|(p, _)| p.to_string()).collect::<HashSet<_>>()
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
        assert_eq!(info.uncompressed_size, buf.len() as u64, "{file} uncompressed size");
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
        .key(key)
        .reader(&mut reader)
        .unwrap();

    let writer = Cursor::new(vec![]);
    let mut pak_writer = repak::PakBuilder::new().writer(
        writer,
        pak_reader.version(),
        pak_reader.mount_point().to_owned(),
        Some(0x205C5A7D),
    );

    for path in pak_reader.files() {
        let data = pak_reader.get(&path, &mut reader).unwrap();
        pak_writer.write_file(&path, false, data).unwrap();
    }

    assert!(pak_writer.write_index().unwrap().into_inner() == reader.into_inner());
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
    ("", /*"_encrypt"*/),
    ("", /*"_encryptindex"*/),
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
    ("", /*"_encryptindex"*/),
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
    let mut w = repak::PakBuilder::new().writer(&mut buf, repak::Version::V12, "../../../".into(), None);
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
    let mut w = repak::PakBuilder::new().writer(&mut buf, repak::Version::V11, "../../../".into(), None);
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
    assert_eq!(rnd.compression, None, "stored when compression doesn't help");
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
        .writer(&mut buf, repak::Version::V11, "../../../Game/Content/".into(), Some(7));
    w.write_file("a.txt", true, b"aaaa".repeat(1000)).unwrap();
    w.write_file("dir/b.txt", true, b"bbbb".repeat(1000)).unwrap();
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
    w.set_compression_options(repak::CompressionOptions { gzip_level: 9, ..Default::default() });
    w.write_file("dir/b.txt", true, b"BBBB".repeat(1000)).unwrap();
    w.write_file("c.txt", true, b"cccc".repeat(1000)).unwrap();
    w.rename_all(|p| format!("Content/{p}")).unwrap();
    w.set_mount_point("../../../Game/".into());
    assert_eq!(w.paths(), ["Content/c.txt", "Content/dir/b.txt"]);
    let out = w.write_index().unwrap();
    let end = out.stream_position().unwrap();
    out.get_mut().truncate(end as usize);
    out.flush().unwrap();
    let bytes = file.into_inner();
    assert!(bytes[..index_offset as usize] == original[..index_offset as usize], "old data untouched");

    let mut r = std::io::Cursor::new(&bytes);
    let pak = repak::PakBuilder::new().reader(&mut r).unwrap();
    assert_eq!(pak.mount_point(), "../../../Game/");
    assert_eq!(pak.path_hash_seed(), Some(7), "seed kept");
    assert_eq!(pak.files(), ["Content/c.txt", "Content/dir/b.txt"]);
    assert_eq!(pak.get("Content/dir/b.txt", &mut r).unwrap(), b"BBBB".repeat(1000));
    assert_eq!(pak.get("Content/c.txt", &mut r).unwrap(), b"cccc".repeat(1000));
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
    assert!(size(repak::CompressionOptions { zlib_level: 9, ..d }, repak::Compression::Zlib)
        <= size(d, repak::Compression::Zlib));
    assert!(size(repak::CompressionOptions { zstd_level: 19, ..d }, repak::Compression::Zstd)
        <= size(repak::CompressionOptions { zstd_level: 1, ..d }, repak::Compression::Zstd));
}
