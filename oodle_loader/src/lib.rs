use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

type Result<T, E = Error> = std::result::Result<T, E>;

pub use oodle_lz::{CompressionLevel, Compressor};

mod oodle_lz {
    #[derive(Debug, Clone, Copy)]
    #[repr(i32)]
    pub enum Compressor {
        /// None = memcpy, pass through uncompressed bytes
        None = 3,

        /// Fast decompression and high compression ratios, amazing!
        Kraken = 8,
        /// Leviathan = Kraken's big brother with higher compression, slightly slower decompression.
        Leviathan = 13,
        /// Mermaid is between Kraken & Selkie - crazy fast, still decent compression.
        Mermaid = 9,
        /// Selkie is a super-fast relative of Mermaid.  For maximum decode speed.
        Selkie = 11,
        /// Hydra, the many-headed beast = Leviathan, Kraken, Mermaid, or Selkie (see $OodleLZ_About_Hydra)
        Hydra = 12,
    }

    #[derive(Debug, Clone, Copy)]
    #[repr(i32)]
    pub enum CompressionLevel {
        /// don't compress, just copy raw bytes
        None = 0,
        /// super fast mode, lower compression ratio
        SuperFast = 1,
        /// fastest LZ mode with still decent compression ratio
        VeryFast = 2,
        /// fast - good for daily use
        Fast = 3,
        /// standard medium speed LZ mode
        Normal = 4,

        /// optimal parse level 1 (faster optimal encoder)
        Optimal1 = 5,
        /// optimal parse level 2 (recommended baseline optimal encoder)
        Optimal2 = 6,
        /// optimal parse level 3 (slower optimal encoder)
        Optimal3 = 7,
        /// optimal parse level 4 (very slow optimal encoder)
        Optimal4 = 8,
        /// optimal parse level 5 (don't care about encode speed, maximum compression)
        Optimal5 = 9,

        /// faster than SuperFast, less compression
        HyperFast1 = -1,
        /// faster than HyperFast1, less compression
        HyperFast2 = -2,
        /// faster than HyperFast2, less compression
        HyperFast3 = -3,
        /// fastest, less compression
        HyperFast4 = -4,
    }

    #[allow(non_snake_case)]
    pub type Compress = unsafe extern "system" fn(
        compressor: Compressor,
        rawBuf: *const u8,
        rawLen: usize,
        compBuf: *mut u8,
        level: CompressionLevel,
        pOptions: *const (),
        dictionaryBase: *const (),
        lrm: *const (),
        scratchMem: *mut u8,
        scratchSize: usize,
    ) -> isize;

    #[allow(non_snake_case)]
    pub type Decompress = unsafe extern "system" fn(
        compBuf: *const u8,
        compBufSize: usize,
        rawBuf: *mut u8,
        rawLen: usize,
        fuzzSafe: u32,
        checkCRC: u32,
        verbosity: u32,
        decBufBase: u64,
        decBufSize: usize,
        fpCallback: u64,
        callbackUserData: u64,
        decoderMemory: *mut u8,
        decoderMemorySize: usize,
        threadPhase: u32,
    ) -> isize;

    #[allow(non_snake_case)]
    pub type GetCompressedBufferSizeNeeded =
        unsafe extern "system" fn(compressor: Compressor, rawSize: usize) -> usize;

    pub type SetPrintf = unsafe extern "system" fn(printf: *const ());
}

#[cfg(feature = "download")]
static OODLE_VERSION: &str = "2.9.10";
#[cfg(feature = "download")]
static OODLE_BASE_URL: &str = "https://github.com/WorkingRobot/OodleUE/raw/refs/heads/main/Engine/Source/Programs/Shared/EpicGames.Oodle/Sdk/";

#[allow(dead_code)]
struct OodlePlatform {
    path: &'static str,
    name: &'static str,
    hash: &'static str,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static OODLE_PLATFORM: OodlePlatform = OodlePlatform {
    path: "linux/lib",
    name: "liboo2corelinux64.so.9",
    hash: "ed7e98f70be1254a80644efd3ae442ff61f854a2fe9debb0b978b95289884e9c",
};

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
static OODLE_PLATFORM: OodlePlatform = OodlePlatform {
    path: "linuxarm/lib",
    name: "liboo2corelinuxarm64.so.9",
    hash: "161a8ecca8cc2d4ea6469779c2cc529ed5bb2765d99466273c29fdbef4657374",
};

#[cfg(all(target_os = "linux", target_arch = "arm"))]
static OODLE_PLATFORM: OodlePlatform = OodlePlatform {
    path: "linuxarm/lib",
    name: "liboo2corelinuxarm32.so.9",
    hash: "83cda016c033844fe650e49fac4cc19ff0a0fb4a3c9a7576a320ea39a9e4626b",
};

#[cfg(target_os = "macos")]
static OODLE_PLATFORM: OodlePlatform = OodlePlatform {
    path: "mac/lib",
    name: "liboo2coremac64.2.9.10.dylib",
    hash: "b09af35f6b84a61e2b6488495c7927e1cef789b969128fa1c845e51a475ec501",
};

#[cfg(windows)]
static OODLE_PLATFORM: OodlePlatform = OodlePlatform {
    path: "win/redist",
    name: "oo2core_9_win64.dll",
    hash: "6f5d41a7892ea6b2db420f2458dad2f84a63901c9a93ce9497337b16c195f457",
};

#[cfg(feature = "download")]
fn url() -> String {
    format!(
        "{OODLE_BASE_URL}/{}/{}/{}",
        OODLE_VERSION, OODLE_PLATFORM.path, OODLE_PLATFORM.name
    )
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Oodle lib hash mismatch expected: {expected} got {found}")]
    HashMismatch { expected: String, found: String },
    #[error("Oodle compression failed")]
    CompressionFailed,
    #[error("Oodle library not found (searched: {})", display_paths(.searched))]
    NotFound { searched: Vec<PathBuf> },
    #[error("IO error {0:?}")]
    Io(#[from] std::io::Error),
    #[cfg(feature = "download")]
    #[error("ureq error {0:?}")]
    Ureq(Box<ureq::Error>),
    #[error("Oodle libloading error {0:?}")]
    LibLoading(#[from] libloading::Error),
}
#[cfg(feature = "download")]
impl From<ureq::Error> for Error {
    fn from(value: ureq::Error) -> Self {
        Self::Ureq(value.into())
    }
}

fn display_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(feature = "download")]
fn check_hash(buffer: &[u8]) -> Result<()> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(buffer);
    let hash = hex::encode(hasher.finalize());
    if hash != OODLE_PLATFORM.hash {
        return Err(Error::HashMismatch {
            expected: OODLE_PLATFORM.hash.into(),
            found: hash,
        });
    }

    Ok(())
}

/// Downloads the known-good Oodle build next to the current executable.
/// Only the downloaded bytes are hash-checked; user-supplied files are not.
#[cfg(feature = "download")]
fn download_oodle() -> Result<PathBuf> {
    let oodle_path = std::env::current_exe()?.with_file_name(OODLE_PLATFORM.name);
    let buffer = ureq::get(&url()).call()?.into_body().read_to_vec()?;
    check_hash(&buffer)?;
    std::fs::write(&oodle_path, buffer)?;
    Ok(oodle_path)
}

/// Extracts N from `oo2core_N_win64.dll` (case-insensitive). Windows naming only.
fn windows_core_version(file_name: &str) -> Option<u32> {
    let lower = file_name.to_ascii_lowercase();
    let rest = lower.strip_prefix("oo2core_")?;
    let rest = rest.strip_suffix("_win64.dll")?;
    rest.parse().ok()
}

/// Finds the best Oodle core library inside `dir`.
/// On Windows any `oo2core_N_win64.dll` is accepted and the highest N wins;
/// elsewhere the platform's canonical file name is used.
fn find_in_dir(dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(u32, PathBuf)> = None;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let version = if cfg!(windows) {
                windows_core_version(name)
            } else if name == OODLE_PLATFORM.name {
                Some(0)
            } else {
                None
            };
            if let Some(v) = version {
                if best.as_ref().is_none_or(|(bv, _)| v > *bv) {
                    best = Some((v, entry.path()));
                }
            }
        }
    }
    best.map(|(_, p)| p)
}

static SEARCH_PATHS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Sets the locations searched for the Oodle core library, in priority order.
/// Each entry may be a directory (scanned for `oo2core_*_win64.dll`) or a file path.
/// When set, these are searched before the executable's directory.
/// Has no effect once Oodle has been loaded successfully.
pub fn set_search_paths<I, P>(paths: I)
where
    I: IntoIterator<Item = P>,
    P: Into<PathBuf>,
{
    let mut guard = SEARCH_PATHS.lock().unwrap_or_else(|e| e.into_inner());
    *guard = paths.into_iter().map(Into::into).collect();
}

fn locate_oodle() -> Result<PathBuf> {
    let searched = search_paths();
    for path in &searched {
        if path.is_file() {
            return Ok(path.clone());
        }
        if let Some(found) = find_in_dir(path) {
            return Ok(found);
        }
    }
    #[cfg(feature = "download")]
    {
        download_oodle()
    }
    #[cfg(not(feature = "download"))]
    {
        Err(Error::NotFound { searched })
    }
}

pub struct Oodle {
    _library: libloading::Library,
    path: PathBuf,
    compress: oodle_lz::Compress,
    decompress: oodle_lz::Decompress,
    get_compressed_buffer_size_needed: oodle_lz::GetCompressedBufferSizeNeeded,
}
impl Oodle {
    /// Path of the loaded library file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn new(lib: libloading::Library, path: PathBuf) -> Result<Self> {
        unsafe {
            let res = Oodle {
                compress: *lib.get(b"OodleLZ_Compress")?,
                decompress: *lib.get(b"OodleLZ_Decompress")?,
                get_compressed_buffer_size_needed: *lib
                    .get(b"OodleLZ_GetCompressedBufferSizeNeeded")?,
                _library: lib,
                path,
            };
            // silence oodle logging; not exported by every oo2core version
            if let Ok(set_printf) = res
                ._library
                .get::<oodle_lz::SetPrintf>(b"OodleCore_Plugins_SetPrintf")
            {
                (set_printf)(std::ptr::null());
            }
            Ok(res)
        }
    }
    pub fn compress(
        &self,
        input: &[u8],
        compressor: Compressor,
        compression_level: CompressionLevel,
    ) -> Result<Vec<u8>> {
        unsafe {
            let buffer_size = self.get_compressed_buffer_size_needed(compressor, input.len());
            let mut buffer = vec![0; buffer_size];

            let len = (self.compress)(
                compressor,
                input.as_ptr(),
                input.len(),
                buffer.as_mut_ptr(),
                compression_level,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            );

            if len == -1 {
                return Err(Error::CompressionFailed);
            }
            buffer.truncate(len as usize);

            Ok(buffer)
        }
    }
    pub fn decompress(&self, input: &[u8], output: &mut [u8]) -> isize {
        unsafe {
            (self.decompress)(
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                output.len(),
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                0,
                3,
            )
        }
    }
    fn get_compressed_buffer_size_needed(
        &self,
        compressor: oodle_lz::Compressor,
        raw_buffer: usize,
    ) -> usize {
        unsafe { (self.get_compressed_buffer_size_needed)(compressor, raw_buffer) }
    }
}

static OODLE: OnceLock<Oodle> = OnceLock::new();
static INIT_LOCK: Mutex<()> = Mutex::new(());

fn load_oodle() -> Result<Oodle> {
    let path = locate_oodle()?;
    unsafe {
        let library = libloading::Library::new(&path)?;
        Oodle::new(library, path)
    }
}

/// Returns the loaded Oodle library, loading it on first successful call.
/// Failures are not cached: a later call retries, so a library added after
/// a failed attempt is picked up without restarting the host process.
pub fn oodle() -> Result<&'static Oodle> {
    if let Some(oodle) = OODLE.get() {
        return Ok(oodle);
    }
    let _guard = INIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(oodle) = OODLE.get() {
        return Ok(oodle);
    }
    let oodle = load_oodle()?;
    Ok(OODLE.get_or_init(|| oodle))
}

/// The locations that would be searched right now, in order (for diagnostics).
pub fn search_paths() -> Vec<PathBuf> {
    let mut paths = SEARCH_PATHS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    {
        paths.push(exe_dir);
    }
    paths
}

/// True if Oodle is already loaded; never triggers a load.
pub fn is_loaded() -> bool {
    OODLE.get().is_some()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses_windows_core_names() {
        assert_eq!(windows_core_version("oo2core_9_win64.dll"), Some(9));
        assert_eq!(windows_core_version("OO2CORE_5_WIN64.DLL"), Some(5));
        assert_eq!(windows_core_version("oo2core_9_win32.dll"), None);
        assert_eq!(windows_core_version("oo2net_9_win64.dll"), None);
    }

    #[test]
    #[cfg_attr(not(feature = "download"), ignore = "needs the Oodle library")]
    fn test_oodle() {
        let oodle = oodle().unwrap();

        let data = b"In tools and when compressing large inputs in one call, consider using
        $OodleXLZ_Compress_AsyncAndWait (in the Oodle2 Ext lib) instead to get parallelism. Alternatively,
        chop the data into small fixed size chunks (we recommend at least 256KiB, i.e. 262144 bytes) and
        call compress on each of them, which decreases compression ratio but makes for trivial parallel
        compression and decompression.";

        let buffer = oodle
            .compress(data, Compressor::Mermaid, CompressionLevel::Optimal5)
            .unwrap();

        dbg!((data.len(), buffer.len()));

        let mut uncomp = vec![0; data.len()];
        oodle.decompress(&buffer, &mut uncomp);

        assert_eq!(data[..], uncomp[..]);
    }
}
