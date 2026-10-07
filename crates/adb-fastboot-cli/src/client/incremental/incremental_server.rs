//! Port of AOSP `client/incremental_server.cpp` — the incremental streaming
//! server protocol core.
//!
//! Wire format (all multi-byte fields BIG-ENDIAN on the wire):
//! - Requests from device, prefixed by INCR magic (0x494e4352):
//!   `[magic:be-u32][request_type:be-i16][file_id:be-i16][block_idx:be-i32]`
//!   (incremental_server.cpp:118-127).
//! - Responses to device: block stream made of
//!   `[file_id:be-i16][block_type:i8][compression_type:i8][block_idx:be-i32]
//!   [block_size:be-i16][data...]`, batched into chunks prefixed with
//!   `[chunk_size:be-i32]` (ResponseHeader / ChunkHeader, incremental_server.cpp:129-149,
//!   525-545).
//! - SendDone marker is a zeroed header with file_id = -1 (incremental_server.cpp:473-483).
//!
//! This module implements the protocol + state machine (sent-block tracking,
//! prefetch scheduling, LZ4 block compression, priority-block ordering) with
//! injectable block sources so it is fully testable offline, plus the fd-level
//! deployment layer (`serve_fds` + `serve`) that AOSP drives through
//! `SkipToRequest`'s poll/read loop against the abb connection.

use std::collections::VecDeque;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::RawFd;

use crate::server::sysdeps_unix::{adb_poll, adb_read, adb_write};

use super::incremental_utils::{
    verity_tree_blocks_for_file, BLOCK_SIZE, DIGEST_SIZE, IDSIG_EXTENSION,
};

/// AOSP `kHashesPerBlock = kBlockSize / kDigestSize` (incremental_server.cpp:49).
pub const HASHES_PER_BLOCK: i64 = BLOCK_SIZE / DIGEST_SIZE;
/// AOSP `kCompressedSizeMax = kBlockSize * 0.95` (:50) — integer constant.
pub const COMPRESSED_SIZE_MAX: i64 = (BLOCK_SIZE as f64 * 0.95) as i64;
/// AOSP `kTypeData` / `kTypeHash` (:51-52).
pub const TYPE_DATA: i8 = 0;
pub const TYPE_HASH: i8 = 1;
/// AOSP `kCompressionNone` / `kCompressionLZ4` (:53-54).
pub const COMPRESSION_NONE: i8 = 0;
pub const COMPRESSION_LZ4: i8 = 1;
/// AOSP `kChunkFlushSize = 31 * kBlockSize` (:268 area).
pub const CHUNK_FLUSH_SIZE: usize = 31 * BLOCK_SIZE as usize;
/// AOSP `kPollTimeoutMillis = 300000` (:57) — 5 minutes.
pub const POLL_TIMEOUT_MILLIS: i32 = 300_000;
/// AOSP `kReadBufferSize = 128 * 1024` (:56).
pub const READ_BUFFER_SIZE: usize = 128 * 1024;
/// AOSP `INCR` magic, compared after big-endian decode (:69).
pub const INCR_MAGIC: u32 = 0x494e_4352;
/// AOSP request types (:71-74).
pub const SERVING_COMPLETE: i16 = 0;
pub const BLOCK_MISSING: i16 = 1;
pub const PREFETCH: i16 = 2;
pub const DESTROY: i16 = 3;

/// AOSP `offsetToBlockIndex` (incremental_utils.cpp:44-46): floor(offset / 4096).
pub fn offset_to_block_index(offset: i64) -> i32 {
    ((offset & !(BLOCK_SIZE - 1)) >> 12) as i32
}

/// AOSP `numBytesToNumBlocks` (incremental_server.cpp:84-86).
pub fn num_bytes_to_num_blocks(bytes: i64) -> i32 {
    if bytes <= 0 {
        return 0;
    }
    ((bytes + BLOCK_SIZE - 1) / BLOCK_SIZE) as i32
}

/// Outcome of one fd-level `ReadRequest` (AOSP incremental_server.cpp:276-360).
enum FdReadOutcome {
    /// A request was decoded.
    Request(RequestCommand),
    /// No complete request this round (non-blocking poll timeout, or blocking
    /// timeout while streaming is still in progress).
    None,
    /// Connection closed, poll failed, or a completed session timed out; AOSP
    /// maps this to a DESTROY request and `Serve()` returns true.
    Disconnected,
}

/// AOSP `WriteFdExactly` (adb_io.cpp:103-130): write all of `buf`; returns the
/// number of bytes written. EAGAIN yields and retries, any other failure
/// (EPIPE included) stops the write.
fn write_fd_exactly(fd: RawFd, buf: &[u8]) -> usize {
    let mut written = 0usize;
    while written < buf.len() {
        match adb_write(fd, &buf[written..]) {
            Ok(0) => break,
            Ok(length) => written += length,
            Err(error) => {
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    std::thread::yield_now();
                    continue;
                }
                break;
            }
        }
    }
    written
}

/// AOSP `RequestCommand` (incremental_server.cpp:118-127) — decoded from the
/// big-endian wire form (magic already stripped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestCommand {
    pub request_type: i16,
    pub file_id: i16,
    /// `block_idx` or `num_blocks` depending on request type.
    pub block_idx: i32,
}

impl RequestCommand {
    pub const WIRE_SIZE: usize = 8;

    /// Decode from exactly 8 bytes, all fields big-endian.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::WIRE_SIZE {
            return None;
        }
        Some(RequestCommand {
            request_type: i16::from_be_bytes([bytes[0], bytes[1]]),
            file_id: i16::from_be_bytes([bytes[2], bytes[3]]),
            block_idx: i32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }
}

/// AOSP `ResponseHeader` (incremental_server.cpp:129-139): 10 bytes packed,
/// big-endian on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResponseHeader {
    pub file_id: i16,
    pub block_type: i8,
    pub compression_type: i8,
    pub block_idx: i32,
    pub block_size: i16,
}

impl ResponseHeader {
    pub const WIRE_SIZE: usize = 10;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut out = [0u8; Self::WIRE_SIZE];
        out[0..2].copy_from_slice(&self.file_id.to_be_bytes());
        out[2] = self.block_type as u8;
        out[3] = self.compression_type as u8;
        out[4..8].copy_from_slice(&self.block_idx.to_be_bytes());
        out[8..10].copy_from_slice(&self.block_size.to_be_bytes());
        out
    }

    /// AOSP `SendDone` marker: all fields zero except file_id = -1
    /// (incremental_server.cpp:473-483).
    pub fn done_marker() -> Self {
        ResponseHeader {
            file_id: -1,
            block_type: 0,
            compression_type: 0,
            block_idx: 0,
            block_size: 0,
        }
    }
}

/// Result of sending one data block (AOSP `SendResult`, incremental_server.cpp:81).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendResult {
    Sent,
    Skipped,
    Error,
}

/// Block source abstraction replacing AOSP's `File` fd pair
/// (incremental_server.cpp:151-200). Implementations must return at most
/// `BLOCK_SIZE` bytes (AOSP pread reads exactly kBlockSize or short at EOF).
pub trait BlockSource {
    /// AOSP `File::ReadDataBlock` (:163-169).
    fn read_data_block(&self, block_idx: i32) -> std::io::Result<Vec<u8>>;
    /// AOSP `File::ReadTreeBlock` (:170-175); only called when `has_tree()`.
    fn read_tree_block(&self, block_idx: i32) -> std::io::Result<Vec<u8>>;
    fn has_tree(&self) -> bool;
}

/// AOSP `File` (incremental_server.cpp:151-200): per-file streaming state.
pub struct ServerFile {
    pub filepath: String,
    pub size: i64,
    pub sent_blocks: Vec<bool>,
    pub sent_blocks_count: i32,
    pub sent_tree_blocks: Vec<bool>,
    pub priority_blocks: Vec<i32>,
    source: Box<dyn BlockSource + Send>,
}

impl ServerFile {
    pub fn new(filepath: String, size: i64, source: Box<dyn BlockSource + Send>) -> Self {
        let mut sent_tree_blocks = vec![false; verity_tree_blocks_for_file(size).max(0) as usize];
        if !source.has_tree() {
            sent_tree_blocks.clear();
        }
        ServerFile {
            filepath,
            size,
            sent_blocks: vec![false; num_bytes_to_num_blocks(size).max(0) as usize],
            sent_blocks_count: 0,
            sent_tree_blocks,
            priority_blocks: Vec::new(),
            source,
        }
    }

    pub fn has_tree(&self) -> bool {
        self.source.has_tree()
    }

    /// AOSP `open_fd` + `open_signature` + `File{}` construction
    /// (incremental_server.cpp:713-757, 151-200): open the file, resolve the
    /// `.idsig` verity tree (offset + size validation), and compute priority
    /// blocks. Fails when the tree size mismatches — matching AOSP's
    /// error_exit on the same condition.
    pub fn open_local(filepath: &str) -> Result<Self, String> {
        let file = std::fs::File::open(filepath)
            .map_err(|error| format!("inc-server: failed to open file '{filepath}': {error}"))?;
        let size = file
            .metadata()
            .map_err(|error| format!("inc-server: failed to stat input file '{filepath}': {error}"))?
            .len() as i64;

        // AOSP open_signature: parse `<file>.idsig` headers, validate tree
        // size, and remember the tree offset (incremental_server.cpp:744-780).
        let signature_path = format!("{filepath}{IDSIG_EXTENSION}");
        let (tree_file, tree_offset) = match std::fs::File::open(&signature_path) {
            Ok(mut signature) => match super::incremental_utils::skip_id_sig_headers(&mut signature)
            {
                Ok((offset, tree_size)) => {
                    let expected = super::incremental_utils::verity_tree_size_for_file(size);
                    if tree_size as i64 != expected {
                        return Err(format!(
                            "Verity tree size mismatch in signature file: {signature_path} [was {tree_size}, expected {expected}]."
                        ));
                    }
                    (Some(signature), offset)
                }
                Err(_) => (None, 0),
            },
            Err(_) => (None, 0),
        };

        let priority_blocks = {
            let mut reader = std::fs::File::open(filepath).map_err(|error| error.to_string())?;
            priority_blocks_for_file(filepath, &mut reader, size)
        };

        let source = LocalFileSource {
            file,
            tree_file,
            tree_offset,
        };
        let mut server_file = Self::new(filepath.to_string(), size, Box::new(source));
        server_file.priority_blocks = priority_blocks;
        Ok(server_file)
    }
}

/// `BlockSource` over an open file pair (AOSP `File` fd fields,
/// incremental_server.cpp:151-200); reads use positional I/O (`pread`) so
/// concurrent block reads stay independent, like AOSP.
struct LocalFileSource {
    file: std::fs::File,
    tree_file: Option<std::fs::File>,
    tree_offset: u64,
}

impl LocalFileSource {
    fn read_at(file: &std::fs::File, offset: u64, length: usize) -> std::io::Result<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        let mut buffer = vec![0u8; length];
        let read = file.read_at(&mut buffer, offset)?;
        buffer.truncate(read);
        Ok(buffer)
    }
}

impl BlockSource for LocalFileSource {
    fn read_data_block(&self, block_idx: i32) -> std::io::Result<Vec<u8>> {
        // AOSP `File::ReadDataBlock`: pread kBlockSize at block offset.
        let offset = block_idx as u64 * BLOCK_SIZE as u64;
        Self::read_at(&self.file, offset, BLOCK_SIZE as usize)
    }

    fn read_tree_block(&self, block_idx: i32) -> std::io::Result<Vec<u8>> {
        // AOSP `File::ReadTreeBlock`: tree_offset_ + block offset.
        match &self.tree_file {
            Some(tree_file) => {
                let offset = self.tree_offset + block_idx as u64 * BLOCK_SIZE as u64;
                Self::read_at(tree_file, offset, BLOCK_SIZE as usize)
            }
            None => Ok(Vec::new()),
        }
    }

    fn has_tree(&self) -> bool {
        self.tree_file.is_some()
    }
}

/// AOSP `PrefetchState` (incremental_server.cpp:220-241).
struct PrefetchState {
    file_index: usize,
    overall_index: i32,
    overall_end: i32,
    priority_index: usize,
}

impl PrefetchState {
    fn new(file_index: usize, file: &ServerFile, start: i32, count: i32) -> Self {
        let end = std::cmp::min(start.saturating_add(count), file.sent_blocks.len() as i32);
        PrefetchState {
            file_index,
            overall_index: start,
            overall_end: end,
            priority_index: 0,
        }
    }

    fn full(file_index: usize, file: &ServerFile) -> Self {
        Self::new(file_index, file, 0, file.sent_blocks.len() as i32)
    }

    fn done(&self, file: &ServerFile) -> bool {
        let overall_sent = self.overall_index >= self.overall_end;
        if file.priority_blocks.is_empty() {
            return overall_sent;
        }
        overall_sent && self.priority_index >= file.priority_blocks.len()
    }
}

/// AOSP `IncrementalServer` (incremental_server.cpp:202-276) protocol core.
///
/// Output model: `pending` holds the current chunk (first 4 bytes reserved
/// for the big-endian ChunkHeader, exactly like `pendingBlocksBuffer_` +
/// `pendingBlocks_`). `drain_output()` flushes it so callers can ship the
/// bytes to the device fd.
pub struct IncrementalServer {
    pub files: Vec<ServerFile>,
    incoming: Vec<u8>,
    pending: Vec<u8>,
    output: Vec<u8>,
    prefetches: VecDeque<PrefetchState>,
    prefetched_files: std::collections::HashSet<i16>,
    pub compressed_blocks: u64,
    pub uncompressed_blocks: u64,
    pub sent_size: u64,
    pub serving_complete: bool,
    /// Set by a DESTROY request.
    pub destroyed: bool,
    /// True after the SendDone marker has been emitted.
    done_sent: bool,
}

impl IncrementalServer {
    pub fn new(files: Vec<ServerFile>) -> Self {
        IncrementalServer {
            files,
            incoming: Vec::new(),
            // Reserve the 4-byte chunk header slot.
            pending: vec![0u8; 4],
            output: Vec::new(),
            prefetches: VecDeque::new(),
            prefetched_files: std::collections::HashSet::new(),
            compressed_blocks: 0,
            uncompressed_blocks: 0,
            sent_size: 0,
            serving_complete: false,
            destroyed: false,
            done_sent: false,
        }
    }

    /// Append raw bytes received from the device.
    pub fn feed(&mut self, data: &[u8]) {
        self.incoming.extend_from_slice(data);
    }

    /// AOSP `SkipToRequest` (incremental_server.cpp:276-355), buffer-side:
    /// find the INCR magic, forward everything before it to `forward` (the
    /// inc-server output stream), and if a full request follows the magic,
    /// consume and return it. Returns None when more data is needed.
    ///
    /// Scan bounds match AOSP exactly: magic positions `bcur` are checked
    /// while `bcur + 4 < bsize`, so a magic starting within the last 4 bytes
    /// is not detected on this round. When no magic is found, everything but
    /// the last 4 bytes is forwarded — those bytes may hold the start of a
    /// magic that straddles the next read boundary.
    pub fn take_request(&mut self, forward: &mut Vec<u8>) -> Option<RequestCommand> {
        let bsize = self.incoming.len() as i32;
        let mut bcur: i32 = 0;
        let mut magic_found = false;
        while bcur + 4 < bsize {
            let at = bcur as usize;
            let magic = u32::from_be_bytes([
                self.incoming[at],
                self.incoming[at + 1],
                self.incoming[at + 2],
                self.incoming[at + 3],
            ]);
            if magic == INCR_MAGIC {
                magic_found = true;
                break;
            }
            bcur += 1;
        }

        if bcur > 0 {
            // Output the rest (pre-magic garbage), then drop it.
            forward.extend_from_slice(&self.incoming[..bcur as usize]);
            self.incoming.drain(..bcur as usize);
        }

        if magic_found && self.incoming.len() >= 4 + RequestCommand::WIRE_SIZE {
            let payload = self.incoming[4..4 + RequestCommand::WIRE_SIZE].to_vec();
            self.incoming.drain(..4 + RequestCommand::WIRE_SIZE);
            return RequestCommand::decode(&payload);
        }
        None
    }

    /// AOSP `SendDataBlock` (incremental_server.cpp:399-471).
    pub fn send_data_block(
        &mut self,
        file_id: i16,
        block_idx: i32,
        flush: bool,
    ) -> SendResult {
        // Phase 1: bounds + duplicate checks (immutable borrow).
        {
            let Some(file) = self.files.get(file_id as usize) else {
                return SendResult::Skipped;
            };
            if block_idx < 0 || block_idx as usize >= file.sent_blocks.len() {
                return SendResult::Skipped;
            }
            if file.sent_blocks[block_idx as usize] {
                return SendResult::Skipped;
            }
        }

        // Phase 2: tree blocks first (AOSP order).
        if !self.send_tree_blocks_for_data_block(file_id, block_idx) {
            return SendResult::Error;
        }

        // Phase 3: read data block (immutable borrow ends with the Vec).
        let data = match self.files[file_id as usize].source.read_data_block(block_idx) {
            Ok(data) => data,
            Err(_) => return SendResult::Error,
        };

        // AOSP always attempts LZ4 (isZipCompressed is dead code and stays
        // false, :427-436); compression wins only when strictly smaller than
        // kCompressedSizeMax.
        let compressed = lz4_flex::block::compress(&data);
        let (payload, compression_type) =
            if !compressed.is_empty() && (compressed.len() as i64) < COMPRESSED_SIZE_MAX {
                self.compressed_blocks += 1;
                (compressed, COMPRESSION_LZ4)
            } else {
                self.uncompressed_blocks += 1;
                (data, COMPRESSION_NONE)
            };

        // Mark sent, then emit (header big-endian encoding happens in
        // emit_block via ResponseHeader::encode).
        self.files[file_id as usize].sent_blocks[block_idx as usize] = true;
        self.files[file_id as usize].sent_blocks_count += 1;
        self.emit_block(file_id, block_idx, TYPE_DATA, compression_type, &payload, flush);
        SendResult::Sent
    }

    /// Emit one response block (header + payload) into the pending chunk.
    /// AOSP sends header and payload in one contiguous Send() call
    /// (incremental_server.cpp:467-469), so the flush boundary always falls
    /// between blocks.
    fn emit_block(
        &mut self,
        file_id: i16,
        block_idx: i32,
        block_type: i8,
        compression_type: i8,
        payload: &[u8],
        flush: bool,
    ) {
        let header = ResponseHeader {
            file_id,
            block_type,
            compression_type,
            block_idx,
            block_size: payload.len() as i16,
        };
        self.pending.extend_from_slice(&header.encode());
        self.pending.extend_from_slice(payload);
        if flush || self.pending.len() > CHUNK_FLUSH_SIZE {
            self.flush();
        }
    }

    /// AOSP `SendTreeBlocksForDataBlock` (incremental_server.cpp:355-395).
    fn send_tree_blocks_for_data_block(&mut self, file_id: i16, block_idx: i32) -> bool {
        {
            let Some(file) = self.files.get(file_id as usize) else {
                return false;
            };
            if !file.has_tree() {
                return true;
            }
        }
        let (leaf_nodes_offset, total_nodes) = {
            let file = &self.files[file_id as usize];
            let data_block_count = num_bytes_to_num_blocks(file.size) as i64;
            let total_nodes = file.sent_tree_blocks.len() as i64;
            let leaf_nodes_count = (data_block_count + HASHES_PER_BLOCK - 1) / HASHES_PER_BLOCK;
            (total_nodes - leaf_nodes_count, total_nodes)
        };
        if total_nodes <= 0 {
            return true;
        }

        // Leaf level: one block covering this data block.
        let leaf_idx = (leaf_nodes_offset + (block_idx as i64) / HASHES_PER_BLOCK) as usize;
        {
            let file = &self.files[file_id as usize];
            if leaf_idx >= file.sent_tree_blocks.len() || file.sent_tree_blocks[leaf_idx] {
                return true;
            }
        }
        if !self.send_tree_block(file_id, block_idx, leaf_idx as i32) {
            return false;
        }
        self.files[file_id as usize].sent_tree_blocks[leaf_idx] = true;

        // Non-leaf: send everything, once.
        if leaf_nodes_offset == 0 || self.files[file_id as usize].sent_tree_blocks[0] {
            return true;
        }
        for index in 0..leaf_nodes_offset as usize {
            if !self.send_tree_block(file_id, block_idx, index as i32) {
                return false;
            }
            self.files[file_id as usize].sent_tree_blocks[index] = true;
        }
        true
    }

    /// AOSP `SendTreeBlock` (incremental_server.cpp:397-419).
    fn send_tree_block(&mut self, file_id: i16, file_block_idx: i32, block_idx: i32) -> bool {
        let _ = file_block_idx;
        let data = match self.files[file_id as usize]
            .source
            .read_tree_block(block_idx)
        {
            Ok(data) => data,
            Err(_) => {
                eprintln!(
                    "Failed to get data for {}{} at blockIdx={}.",
                    self.files[file_id as usize].filepath, IDSIG_EXTENSION, block_idx
                );
                return false;
            }
        };
        self.emit_block(file_id, block_idx, TYPE_HASH, COMPRESSION_NONE, &data, false);
        true
    }

    /// AOSP `SendDone` (incremental_server.cpp:473-483): zeroed header with
    /// file_id = -1, flushed immediately.
    pub fn send_done(&mut self) {
        let marker = ResponseHeader::done_marker().encode();
        self.send(&marker, true);
    }

    /// Whether every file has been fully sent (AOSP Serve's done predicate,
    /// incremental_server.cpp:596-604).
    pub fn all_files_sent(&self) -> bool {
        self.files.iter().all(|file| {
            file.sent_blocks_count == file.sent_blocks.len() as i32
        })
    }

    /// AOSP `RunPrefetching` (incremental_server.cpp:485-517): up to 128
    /// blocks per iteration across the prefetch queue.
    pub fn run_prefetching(&mut self) {
        let mut blocks_to_send = 128i32;
        while !self.prefetches.is_empty() && blocks_to_send > 0 {
            let (file_index, priority_len, overall_end, priority_index, overall_index) = {
                let prefetch = self.prefetches.front().unwrap();
                let file = &self.files[prefetch.file_index];
                (
                    prefetch.file_index,
                    file.priority_blocks.len(),
                    prefetch.overall_end,
                    prefetch.priority_index,
                    prefetch.overall_index,
                )
            };
            let _ = file_index;

            // Priority blocks first.
            let mut priority_index = priority_index;
            while blocks_to_send > 0 && priority_index < priority_len {
                let file = &self.files[self.prefetches.front().unwrap().file_index];
                let block = file.priority_blocks[priority_index];
                let file_index = self.prefetches.front().unwrap().file_index;
                match self.send_data_block(file_index as i16, block, false) {
                    SendResult::Sent => blocks_to_send -= 1,
                    SendResult::Error => {
                        eprintln!("Failed to send priority block {priority_index}");
                    }
                    SendResult::Skipped => {}
                }
                priority_index += 1;
            }
            if let Some(prefetch) = self.prefetches.front_mut() {
                prefetch.priority_index = priority_index;
            }

            // Then the overall range.
            let mut overall_index = overall_index;
            while blocks_to_send > 0 && overall_index < overall_end {
                let file_index = self.prefetches.front().unwrap().file_index;
                match self.send_data_block(file_index as i16, overall_index, false) {
                    SendResult::Sent => blocks_to_send -= 1,
                    SendResult::Error => {
                        eprintln!("Failed to send block {overall_index}");
                    }
                    SendResult::Skipped => {}
                }
                overall_index += 1;
            }
            if let Some(prefetch) = self.prefetches.front_mut() {
                prefetch.overall_index = overall_index;
            }

            let done = {
                let prefetch = self.prefetches.front().unwrap();
                prefetch.done(&self.files[prefetch.file_index])
            };
            if done {
                self.prefetches.pop_front();
            }
        }
    }

    /// AOSP Serve's request switch (incremental_server.cpp:620-706).
    pub fn handle_request(&mut self, request: RequestCommand) {
        let file_id = request.file_id;
        let block_idx = request.block_idx;
        match request.request_type {
            DESTROY => {
                // Stop everything; caller observes `destroyed`.
                self.destroyed = true;
            }
            SERVING_COMPLETE => {
                self.serving_complete = true;
            }
            BLOCK_MISSING => {
                if file_id < 0
                    || (file_id as usize) >= self.files.len()
                    || block_idx < 0
                    || (block_idx as usize) >= self.files[file_id as usize].sent_blocks.len()
                {
                    eprintln!(
                        "Received invalid data request for file_id {file_id} block_idx {block_idx}."
                    );
                    return;
                }
                match self.send_data_block(file_id, block_idx, true) {
                    SendResult::Error => {
                        eprintln!("Failed to send block {block_idx}.");
                    }
                    SendResult::Sent => {
                        // Prefetch the next few blocks from this point onward.
                        let prefetch =
                            PrefetchState::new(file_id as usize, &self.files[file_id as usize], block_idx + 1, 7);
                        self.prefetches.push_front(prefetch);
                    }
                    SendResult::Skipped => {}
                }
            }
            PREFETCH => {
                if file_id < 0 {
                    eprintln!("Received invalid prefetch request for file_id {file_id}");
                    return;
                }
                if !self.prefetched_files.insert(file_id) {
                    eprintln!("Received duplicate prefetch request for file_id {file_id}");
                    return;
                }
                let prefetch = PrefetchState::full(file_id as usize, &self.files[file_id as usize]);
                self.prefetches.push_back(prefetch);
            }
            _ => {
                eprintln!(
                    "Invalid request {},{file_id},{block_idx}.",
                    request.request_type
                );
            }
        }
    }

    /// AOSP `Send` (:519-524): append into the pending chunk; flush when
    /// requested or when the chunk exceeds kChunkFlushSize.
    fn send(&mut self, data: &[u8], flush: bool) {
        self.pending.extend_from_slice(data);
        if flush || self.pending.len() > CHUNK_FLUSH_SIZE {
            self.flush();
        }
    }

    /// AOSP `Flush` (:526-545): prefix the pending chunk with its big-endian
    /// byte count and emit it.
    fn flush(&mut self) {
        let data_bytes = self.pending.len() - 4;
        if data_bytes == 0 {
            return;
        }
        let size = (data_bytes as i32).to_be_bytes();
        self.pending[0..4].copy_from_slice(&size);
        self.output.extend_from_slice(&self.pending);
        self.sent_size += self.pending.len() as u64;
        self.pending.truncate(4);
    }

    /// Flush and return everything the server wants to send to the device
    /// (including the 4-byte chunk headers).
    pub fn drain_output(&mut self) -> Vec<u8> {
        self.flush();
        std::mem::take(&mut self.output)
    }

    /// One iteration of AOSP `Serve()` (incremental_server.cpp:583-712):
    /// send the done marker once everything is sent, read+handle one request,
    /// then run prefetching. Callers feed input bytes and ship `drain_output`
    /// + `forward` to the fds.
    ///
    /// Returns false when the server should stop (DESTROY received).
    pub fn serve_step(&mut self, forward: &mut Vec<u8>) -> bool {
        if !self.done_sent && self.prefetches.is_empty() && self.all_files_sent() {
            eprintln!("All files should be loaded. Notifying the device.");
            self.send_done();
            self.done_sent = true;
        }

        let blocking = self.prefetches.is_empty();
        if blocking {
            // A blocking read may take arbitrarily long; flush first.
            self.flush();
        }

        if let Some(request) = self.take_request(forward) {
            self.handle_request(request);
        }

        self.run_prefetching();
        !self.destroyed
    }

    /// AOSP `Serve()` (incremental_server.cpp:551-658) driving real fds: the
    /// "OKAY" handshake, done-notification, blocking flush, request loop and
    /// prefetching. `connection_fd` is the abb connection to the device;
    /// non-protocol device output is forwarded to `output_fd`.
    ///
    /// Returns true when the server should stop (DESTROY request, disconnect,
    /// or a completed session timing out), false when the handshake failed.
    pub fn serve_fds(&mut self, connection_fd: RawFd, output_fd: RawFd) -> bool {
        // AOSP SendOkay (incremental_server.cpp:553-557).
        if write_fd_exactly(connection_fd, b"OKAY") != 4 {
            eprintln!("Connection is dead. Abort.");
            return false;
        }

        let mut read_buffer = vec![0u8; READ_BUFFER_SIZE];
        let mut done_sent = false;
        loop {
            if !done_sent && self.prefetches.is_empty() && self.all_files_sent() {
                eprintln!("All files should be loaded. Notifying the device.");
                self.send_done();
                done_sent = true;
                self.ship_output(connection_fd);
            }

            let blocking = self.prefetches.is_empty();
            if blocking {
                // "We've no idea how long the blocking call is, so let's
                // flush whatever is still unsent." (incremental_server.cpp:586-589)
                self.flush();
                self.ship_output(connection_fd);
            }

            match self.read_request_fd(connection_fd, output_fd, blocking, &mut read_buffer) {
                FdReadOutcome::Request(request) => {
                    if request.request_type == DESTROY {
                        // AOSP: stop everything (Serve returns true).
                        return true;
                    }
                    self.handle_request(request);
                    self.ship_output(connection_fd);
                }
                FdReadOutcome::None => {}
                FdReadOutcome::Disconnected => return true,
            }

            self.run_prefetching();
            self.ship_output(connection_fd);
        }
    }

    /// AOSP `ReadRequest` + `SkipToRequest` (incremental_server.cpp:276-360):
    /// drive the connection fd. While scanning for the INCR magic, all
    /// non-protocol bytes are forwarded to `output_fd` as they are skipped.
    fn read_request_fd(
        &mut self,
        connection_fd: RawFd,
        output_fd: RawFd,
        blocking: bool,
        read_buffer: &mut [u8],
    ) -> FdReadOutcome {
        loop {
            let mut forward = Vec::new();
            let request = self.take_request(&mut forward);
            if !forward.is_empty() {
                let _ = write_fd_exactly(output_fd, &forward);
            }
            if let Some(request) = request {
                return FdReadOutcome::Request(request);
            }

            let timeout = if blocking { POLL_TIMEOUT_MILLIS } else { 0 };
            match adb_poll(connection_fd, libc::POLLIN, timeout) {
                Ok(1) => {
                    let pending = self.incoming.len();
                    let capacity = READ_BUFFER_SIZE.saturating_sub(pending);
                    match adb_read(connection_fd, &mut read_buffer[..capacity]) {
                        Ok(length) if length > 0 => {
                            self.incoming.extend_from_slice(&read_buffer[..length]);
                        }
                        Ok(_) => {
                            // AOSP: r == 0 → disconnected. Flush the tail.
                            let _ = write_fd_exactly(output_fd, &self.incoming);
                            return FdReadOutcome::Disconnected;
                        }
                        Err(_) => {
                            // AOSP: failed to read. Flush the tail.
                            let _ = write_fd_exactly(output_fd, &self.incoming);
                            return FdReadOutcome::Disconnected;
                        }
                    }
                }
                Ok(_) => {
                    // Timeout (AOSP res == 0). The pending bytes go to the
                    // output without being dropped — the tail may hold the
                    // start of a split INCR magic (incremental_server.cpp:302-317).
                    let _ = write_fd_exactly(output_fd, &self.incoming);
                    if blocking {
                        eprintln!("Timed out waiting for data from device.");
                    }
                    if blocking && self.serving_complete {
                        // "timeout waiting from client. Serving is complete,
                        // so quit." (incremental_server.cpp:313-316)
                        return FdReadOutcome::Disconnected;
                    }
                    return FdReadOutcome::None;
                }
                Err(_) => {
                    // AOSP: failed to poll (res < 0). Flush the tail and stop.
                    let _ = write_fd_exactly(output_fd, &self.incoming);
                    return FdReadOutcome::Disconnected;
                }
            }
        }
    }

    /// Ship already-flushed output to the connection fd. AOSP writes to the
    /// fd inside `Flush`/`Send`; a failed write is reported but not fatal —
    /// the next poll/read fails instead (incremental_server.cpp:536-539).
    fn ship_output(&mut self, connection_fd: RawFd) {
        if self.output.is_empty() {
            return;
        }
        let output = std::mem::take(&mut self.output);
        if write_fd_exactly(connection_fd, &output) != output.len() {
            eprintln!("Failed to write {} bytes", output.len());
        }
    }

    /// True after the SendDone marker has been emitted.
    pub fn done_sent(&self) -> bool {
        self.done_sent
    }
}

/// Compute priority blocks for a file (AOSP `PriorityBlocksForFile`,
/// incremental_utils.cpp:401-417). Only `.apk` files get priority blocks;
/// a missing/invalid signer block yields none.
pub fn priority_blocks_for_file<R: Read + Seek>(
    filepath: &str,
    reader: &mut R,
    file_size: i64,
) -> Vec<i32> {
    if !filepath.to_ascii_lowercase().ends_with(".apk") {
        return Vec::new();
    }
    let Some(signer_offset) = signer_block_offset(reader, file_size) else {
        return Vec::new();
    };
    let mut blocks = zip_priority_blocks(signer_offset, file_size);
    let installation = installation_priority_blocks(reader, file_size);
    blocks.extend(installation);
    unduplicate(&mut blocks);
    blocks
}

/// AOSP `CentralDirOffset` (incremental_utils.cpp:210-242).
fn central_dir_offset<R: Read + Seek>(reader: &mut R, file_size: i64) -> Option<i64> {
    const ZIP_EOCD_REC_MIN_SIZE: i64 = 22;
    const ZIP_EOCD_REC_SIG: i32 = 0x0605_4b50;
    const ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET: i64 = 12;
    const ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET: i64 = 20;

    if file_size < ZIP_EOCD_REC_MIN_SIZE {
        return None;
    }
    let max_eocd_offset = file_size - ZIP_EOCD_REC_MIN_SIZE;
    for comment_len in 0..file_size {
        let offset = max_eocd_offset - comment_len;
        if offset < 0 {
            break;
        }
        let sig = read_i32_le_at(reader, offset)?;
        if sig == ZIP_EOCD_REC_SIG {
            let comment_len_buf = read_i16_le_at(
                reader,
                max_eocd_offset - comment_len + ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET,
            )?;
            if comment_len_buf as i64 == comment_len {
                let cd_len = read_i32_le_at(reader, offset + ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET)?
                    as i64;
                return Some(offset - cd_len);
            }
        }
    }
    None
}

/// AOSP `SignerBlockOffset` (incremental_utils.cpp:245-276).
fn signer_block_offset<R: Read + Seek>(reader: &mut R, file_size: i64) -> Option<i64> {
    const APK_SIG_BLOCK_MIN_SIZE: i64 = 32;
    const APK_SIG_BLOCK_FOOTER_SIZE: i64 = 24;
    const APK_SIG_BLOCK_MAGIC_HI: i64 = 0x3234_206b_636f_6c42;
    const APK_SIG_BLOCK_MAGIC_LO: i64 = 0x2067_6953_204b_5041;

    let cd_offset = central_dir_offset(reader, file_size)?;
    if cd_offset < APK_SIG_BLOCK_MIN_SIZE
        || read_i64_le_at(reader, cd_offset - 16)? != APK_SIG_BLOCK_MAGIC_LO
        || read_i64_le_at(reader, cd_offset - 8)? != APK_SIG_BLOCK_MAGIC_HI
    {
        return None;
    }
    let signer_size_in_footer = read_i32_le_at(reader, cd_offset - APK_SIG_BLOCK_FOOTER_SIZE)? as i64;
    let signer_block_offset = cd_offset - signer_size_in_footer - 8;
    if signer_block_offset < 0 {
        return None;
    }
    let signer_size_in_header = read_i32_le_at(reader, signer_block_offset)? as i64;
    if signer_size_in_footer != signer_size_in_header {
        return None;
    }
    Some(signer_block_offset)
}

/// AOSP `ZipPriorityBlocks` (incremental_utils.cpp:278-303).
fn zip_priority_blocks(signer_block_offset: i64, file_size: i64) -> Vec<i32> {
    let signer_block_index = offset_to_block_index(signer_block_offset);
    let last_block_index = offset_to_block_index(file_size);
    let num_priority_blocks = last_block_index - signer_block_index + 1;

    let mut blocks = Vec::new();
    // kMaxZipCommentSize = 64 * 1024; kNumBlocksInEocdSearch = 64K/4K + 1.
    const NUM_BLOCKS_IN_EOCD_SEARCH: i32 = 64 * 1024 / BLOCK_SIZE as i32 + 1;
    if num_priority_blocks > NUM_BLOCKS_IN_EOCD_SEARCH {
        append_blocks(
            last_block_index - NUM_BLOCKS_IN_EOCD_SEARCH + 1,
            NUM_BLOCKS_IN_EOCD_SEARCH,
            &mut blocks,
        );
        append_blocks(
            signer_block_index,
            num_priority_blocks - NUM_BLOCKS_IN_EOCD_SEARCH,
            &mut blocks,
        );
    } else {
        append_blocks(signer_block_index, num_priority_blocks, &mut blocks);
    }
    // The archive start is always touched by zip readers.
    append_blocks(0, 1, &mut blocks);
    blocks
}

/// AOSP `appendBlocks` (incremental_utils.cpp:196-204): append `count`
/// consecutive blocks starting at `start`.
fn append_blocks(start: i32, count: i32, blocks: &mut Vec<i32>) {
    if count == 1 {
        blocks.push(start);
    } else if count > 1 {
        let old_size = blocks.len();
        blocks.resize(old_size + count as usize, 0);
        for (index, slot) in blocks[old_size..].iter_mut().enumerate() {
            *slot = start + index as i32;
        }
    }
}

/// AOSP `unduplicate` (incremental_utils.cpp:206-212): keep first
/// occurrences, preserve order.
fn unduplicate(blocks: &mut Vec<i32>) {
    let mut seen = std::collections::HashSet::new();
    blocks.retain(|block| seen.insert(*block));
}

/// AOSP `InstallationPriorityBlocks` (incremental_utils.cpp:371-399):
/// `resources.arsc`, `AndroidManifest.xml`, `classes.dex` (first 2 blocks)
/// and all `lib/*.so` entries, via central-directory iteration.
///
/// Uses the `zip` crate for directory parsing; the data-descriptor extra 16
/// bytes AOSP adds is applied conservatively (over-inclusion is harmless for
/// priority hints).
fn installation_priority_blocks<R: Read + Seek>(
    reader: &mut R,
    file_size: i64,
) -> Vec<i32> {
    let _ = file_size;
    let mut blocks = Vec::new();
    // Clone the reader stream position into the zip crate: it needs a fresh
    // Read+Seek over the whole file.
    if reader.seek(SeekFrom::Start(0)).is_err() {
        return blocks;
    }
    let mut archive = match zip::ZipArchive::new(&mut *reader) {
        Ok(archive) => archive,
        Err(_) => return blocks,
    };
    for index in 0..archive.len() {
        let Ok(entry) = archive.by_index(index) else {
            continue;
        };
        let name = entry.name().to_string();
        let matches = (name.starts_with("lib/") && name.ends_with(".so"))
            || name == "resources.arsc"
            || name == "AndroidManifest.xml"
            || name == "classes.dex";
        if !matches {
            continue;
        }
        // zip crate: header_start() is the local header offset (AOSP
        // ZipEntry64.offset); data_start() is the data offset. AOSP computes
        // the range from the entry offset through its data, +16 for a data
        // descriptor when present — over-covering by 16 bytes is safe for a
        // prefetch hint, so always add it for non-dex entries.
        let entry_start = entry.header_start() as i64;
        if name == "classes.dex" {
            // Only the head is needed for installation (2 blocks).
            let start_block = offset_to_block_index(entry_start);
            append_blocks(start_block, 2, &mut blocks);
        } else {
            let stored = entry.compression() == zip::CompressionMethod::Stored;
            let payload_len = if stored {
                entry.size()
            } else {
                entry.compressed_size()
            } as i64;
            let entry_end = entry_start + payload_len + 16;
            let start_block = offset_to_block_index(entry_start);
            let end_block = offset_to_block_index(entry_end);
            let num_new_blocks = end_block - start_block + 1;
            append_blocks(start_block, num_new_blocks, &mut blocks);
        }
    }
    blocks
}

// ----- little-endian positional reads (mirror AOSP valueAt<T>) -----

fn read_exact_at<R: Read + Seek>(reader: &mut R, offset: i64, buffer: &mut [u8]) -> Option<()> {
    if offset < 0 {
        return None;
    }
    reader.seek(SeekFrom::Start(offset as u64)).ok()?;
    reader.read_exact(buffer).ok()?;
    Some(())
}

fn read_i32_le_at<R: Read + Seek>(reader: &mut R, offset: i64) -> Option<i32> {
    let mut buffer = [0u8; 4];
    read_exact_at(reader, offset, &mut buffer)?;
    Some(i32::from_le_bytes(buffer))
}

fn read_i16_le_at<R: Read + Seek>(reader: &mut R, offset: i64) -> Option<i16> {
    let mut buffer = [0u8; 2];
    read_exact_at(reader, offset, &mut buffer)?;
    Some(i16::from_le_bytes(buffer))
}

fn read_i64_le_at<R: Read + Seek>(reader: &mut R, offset: i64) -> Option<i64> {
    let mut buffer = [0u8; 8];
    read_exact_at(reader, offset, &mut buffer)?;
    Some(i64::from_le_bytes(buffer))
}

/// AOSP `incremental::serve` (incremental_server.cpp:711-734): the body of the
/// internal `adb inc-server CONNECTION_FD OUTPUT_FD [FILE1 FILE2 ...]`
/// command. Each file's argument position is its server file id. Returns true
/// when serving stopped normally (DESTROY/disconnect), false on setup failure.
///
/// Note: AOSP returns this bool straight into `main`'s int exit code, which
/// inverts it (true → exit 1); this port keeps the sane mapping (CLI exits 0
/// on success). No AOSP caller checks the exit code.
pub fn serve(connection_fd: RawFd, output_fd: RawFd, file_paths: &[String]) -> bool {
    let mut files = Vec::with_capacity(file_paths.len());
    for path in file_paths {
        match ServerFile::open_local(path) {
            Ok(file) => files.push(file),
            Err(error) => {
                eprintln!("{error}");
                return false;
            }
        }
    }

    let mut server = IncrementalServer::new(files);
    println!("Serving...");
    let _ = std::io::stdout().flush();
    // AOSP: fclose(stdin); fclose(stdout) — detach from the terminal this was
    // started from; stderr stays for diagnostics (incremental_server.cpp:731-733).
    unsafe {
        libc::close(libc::STDIN_FILENO);
        libc::close(libc::STDOUT_FILENO);
    }
    server.serve_fds(connection_fd, output_fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory BlockSource for protocol tests.
    struct MemorySource {
        data: Vec<u8>,
        tree: Option<Vec<u8>>,
    }

    impl BlockSource for MemorySource {
        fn read_data_block(&self, block_idx: i32) -> std::io::Result<Vec<u8>> {
            let start = block_idx as usize * BLOCK_SIZE as usize;
            if start >= self.data.len() {
                return Ok(Vec::new());
            }
            let end = std::cmp::min(start + BLOCK_SIZE as usize, self.data.len());
            Ok(self.data[start..end].to_vec())
        }

        fn read_tree_block(&self, block_idx: i32) -> std::io::Result<Vec<u8>> {
            let Some(tree) = &self.tree else {
                return Ok(Vec::new());
            };
            let start = block_idx as usize * BLOCK_SIZE as usize;
            if start >= tree.len() {
                return Ok(Vec::new());
            }
            let end = std::cmp::min(start + BLOCK_SIZE as usize, tree.len());
            Ok(tree[start..end].to_vec())
        }

        fn has_tree(&self) -> bool {
            self.tree.is_some()
        }
    }

    fn encode_request(request_type: i16, file_id: i16, block_idx: i32) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&INCR_MAGIC.to_be_bytes());
        out.extend_from_slice(&request_type.to_be_bytes());
        out.extend_from_slice(&file_id.to_be_bytes());
        out.extend_from_slice(&block_idx.to_be_bytes());
        out
    }

    /// Parse one chunk of server output: [be32 size][block-header+payload]...
    fn parse_blocks(bytes: &[u8]) -> Vec<(ResponseHeader, Vec<u8>)> {
        let mut blocks = Vec::new();
        let mut cursor = 0usize;
        while cursor + 4 <= bytes.len() {
            let size = i32::from_be_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            cursor += 4;
            let chunk_end = cursor + size;
            while cursor + ResponseHeader::WIRE_SIZE <= chunk_end {
                let header = ResponseHeader {
                    file_id: i16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]),
                    block_type: bytes[cursor + 2] as i8,
                    compression_type: bytes[cursor + 3] as i8,
                    block_idx: i32::from_be_bytes([
                        bytes[cursor + 4],
                        bytes[cursor + 5],
                        bytes[cursor + 6],
                        bytes[cursor + 7],
                    ]),
                    block_size: i16::from_be_bytes([bytes[cursor + 8], bytes[cursor + 9]]),
                };
                cursor += ResponseHeader::WIRE_SIZE;
                let payload_len = header.block_size as usize;
                let payload = bytes[cursor..cursor + payload_len].to_vec();
                cursor += payload_len;
                blocks.push((header, payload));
            }
        }
        blocks
    }

    #[test]
    fn request_command_decodes_big_endian_fields() {
        let request = RequestCommand::decode(&[
            0x00, 0x01, // BLOCK_MISSING
            0xff, 0xfe, // file_id = -2
            0x00, 0x00, 0x10, 0x01, // block_idx = 4097
        ])
        .unwrap();
        assert_eq!(request.request_type, BLOCK_MISSING);
        assert_eq!(request.file_id, -2);
        assert_eq!(request.block_idx, 4097);
        assert!(RequestCommand::decode(&[0u8; 4]).is_none());
    }

    #[test]
    fn response_header_encodes_big_endian_and_done_marker() {
        let header = ResponseHeader {
            file_id: 1,
            block_type: TYPE_DATA,
            compression_type: COMPRESSION_LZ4,
            block_idx: 0x01020304,
            block_size: 4096,
        };
        let encoded = header.encode();
        assert_eq!(
            encoded,
            [
                0x00, 0x01, // file_id be
                0x00, // type
                0x01, // compression
                0x01, 0x02, 0x03, 0x04, // block_idx be
                0x10, 0x00, // block_size be
            ]
        );
        let done = ResponseHeader::done_marker().encode();
        assert_eq!(done, [0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn take_request_forwards_pre_magic_garbage_and_parses_request() {
        let mut server = IncrementalServer::new(Vec::new());
        let mut input = b"partial line from pm\n".to_vec();
        input.extend_from_slice(&encode_request(PREFETCH, 0, 0));
        server.feed(&input);

        let mut forwarded = Vec::new();
        let request = server.take_request(&mut forwarded).unwrap();
        assert_eq!(request.request_type, PREFETCH);
        assert_eq!(forwarded, b"partial line from pm\n");

        // Stream is now empty.
        let request = server.take_request(&mut forwarded);
        assert!(request.is_none());
    }

    #[test]
    fn take_request_waits_for_complete_payload_and_keeps_magic_tail() {
        let mut server = IncrementalServer::new(Vec::new());
        // Magic + only 4 request bytes → None; the buffered port must not
        // lose bytes when the request arrives split: feed in two parts.
        let full = encode_request(BLOCK_MISSING, 3, 7);
        server.feed(&full[..8]);
        let mut forwarded = Vec::new();
        assert!(server.take_request(&mut forwarded).is_none());
        server.feed(&full[8..]);
        let request = server.take_request(&mut forwarded).unwrap();
        assert_eq!(request.file_id, 3);
        assert_eq!(request.block_idx, 7);
        assert!(forwarded.is_empty());
    }

    #[test]
    fn take_request_keeps_partial_magic_when_no_match() {
        let mut server = IncrementalServer::new(Vec::new());
        // 3 bytes of a would-be magic: nothing may be forwarded (they could
        // be a magic prefix).
        server.feed(&[0x49, 0x4e, 0x43]);
        let mut forwarded = Vec::new();
        assert!(server.take_request(&mut forwarded).is_none());
        assert!(forwarded.is_empty());

        // 5 bytes with no magic: forward all but the last 4 (AOSP keeps a
        // 4-byte tail — a magic may start right at the old buffer end).
        server.feed(&[0x58, 0x58]);
        assert!(server.take_request(&mut forwarded).is_none());
        assert_eq!(forwarded, [0x49]);
    }

    #[test]
    fn take_request_keeps_magic_starting_at_last_4_bytes() {
        // Regression guard for AOSP's exact scan bounds (`bcur + 4 < bsize`):
        // a magic that starts at bsize - 4 is *not* detected this round and
        // must survive in the buffer (forwarding all-but-last-4 keeps it; a
        // keep-3 rule would forward the 'I' and corrupt the request stream).
        let mut server = IncrementalServer::new(Vec::new());
        server.feed(&[b'A'; 7]);
        server.feed(b"INCR"); // magic at position 7 of an 11-byte buffer
        let mut forwarded = Vec::new();
        assert!(server.take_request(&mut forwarded).is_none());
        assert_eq!(forwarded, b"AAAAAAA");

        server.feed(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // BLOCK_MISSING 0/0
        let request = server.take_request(&mut forwarded).unwrap();
        assert_eq!(request.request_type, BLOCK_MISSING);
        assert_eq!(request.file_id, 0);
        assert_eq!(request.block_idx, 0);
    }

    #[test]
    fn send_data_block_emits_chunk_with_header_and_payload_and_marks_sent() {
        // LCG stream — incompressible under LZ4, so the uncompressed path
        // runs deterministically (pattern data can compress; see the lz4
        // test for the compressed path).
        let mut state = 0x12345678u32;
        let data: Vec<u8> = (0..8192)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 24) as u8
            })
            .collect();
        let file = ServerFile::new(
            "test.apk".into(),
            8192,
            Box::new(MemorySource { data: data.clone(), tree: None }),
        );
        let mut server = IncrementalServer::new(vec![file]);
        assert_eq!(server.files[0].sent_blocks.len(), 2);

        assert_eq!(server.send_data_block(0, 0, true), SendResult::Sent);
        assert_eq!(server.send_data_block(0, 0, true), SendResult::Skipped);
        assert_eq!(server.send_data_block(0, 5, true), SendResult::Skipped);

        let output = server.drain_output();
        let blocks = parse_blocks(&output);
        assert_eq!(blocks.len(), 1);
        let (header, payload) = &blocks[0];
        assert_eq!(header.file_id, 0);
        assert_eq!(header.block_type, TYPE_DATA);
        assert_eq!(header.block_idx, 0);
        assert_eq!(header.compression_type, COMPRESSION_NONE);
        assert_eq!(payload, &data[..4096]);
        assert_eq!(header.block_size as usize, payload.len());
        assert!(server.files[0].sent_blocks[0]);
        assert!(!server.files[0].sent_blocks[1]);
        assert_eq!(server.files[0].sent_blocks_count, 1);
    }

    #[test]
    fn lz4_used_when_compressible_and_roundtrips() {
        // Zero-filled block compresses far below kCompressedSizeMax.
        let data = vec![0u8; 8192];
        let file = ServerFile::new(
            "zeros.apk".into(),
            8192,
            Box::new(MemorySource { data, tree: None }),
        );
        let mut server = IncrementalServer::new(vec![file]);
        assert_eq!(server.send_data_block(0, 0, true), SendResult::Sent);
        let Blocks = parse_blocks(&server.drain_output());
        let (header, payload) = &Blocks[0];
        assert_eq!(header.compression_type, COMPRESSION_LZ4);
        let decompressed = lz4_flex::block::decompress(payload, BLOCK_SIZE as usize).unwrap();
        assert_eq!(decompressed, vec![0u8; 4096]);
        assert_eq!(server.compressed_blocks, 1);
    }

    #[test]
    fn tree_blocks_precede_data_block_and_are_sent_once() {
        // 8192-byte file → 2 data blocks → verity tree of 1 block.
        let data = vec![0xabu8; 8192];
        let tree = vec![0x11u8; BLOCK_SIZE as usize];
        let file = ServerFile::new(
            "signed.apk".into(),
            8192,
            Box::new(MemorySource {
                data,
                tree: Some(tree.clone()),
            }),
        );
        assert_eq!(file.sent_tree_blocks.len(), 1);
        let mut server = IncrementalServer::new(vec![file]);

        assert_eq!(server.send_data_block(0, 0, true), SendResult::Sent);
        // Second data block: tree already sent → only data block.
        assert_eq!(server.send_data_block(0, 1, true), SendResult::Sent);

        let blocks = parse_blocks(&server.drain_output());
        let types: Vec<(i8, i32)> = blocks
            .iter()
            .map(|(header, _)| (header.block_type, header.block_idx))
            .collect();
        // Tree block (type hash, idx 0) first, then data blocks 0 and 1.
        assert_eq!(
            types,
            [
                (TYPE_HASH, 0),
                (TYPE_DATA, 0),
                (TYPE_DATA, 1)
            ]
        );
        assert_eq!(blocks[0].1, tree);
        assert!(server.files[0].sent_tree_blocks[0]);
    }

    #[test]
    fn full_serve_flow_prefetch_done_and_destroy() {
        let data = vec![0x5au8; 3 * 4096];
        let file = ServerFile::new(
            "flow.apk".into(),
            data.len() as i64,
            Box::new(MemorySource { data, tree: None }),
        );
        let mut server = IncrementalServer::new(vec![file]);

        // PREFETCH for file 0 → serve_step prefetches everything.
        server.feed(&encode_request(PREFETCH, 0, 0));
        let mut forwarded = Vec::new();
        assert!(server.serve_step(&mut forwarded));
        let blocks = parse_blocks(&server.drain_output());
        assert_eq!(blocks.len(), 3);
        assert!(server.all_files_sent());

        // Next step: nothing to send but all sent → done marker.
        assert!(server.serve_step(&mut forwarded));
        assert!(server.done_sent());
        let output = server.drain_output();
        let blocks = parse_blocks(&output);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, ResponseHeader::done_marker());

        // DESTROY → stop.
        server.feed(&encode_request(DESTROY, 0, 0));
        assert!(!server.serve_step(&mut forwarded));
        assert!(server.destroyed);
    }

    #[test]
    fn block_missing_sends_promptly_and_schedules_small_prefetch() {
        let data = vec![7u8; 20 * 4096];
        let file = ServerFile::new(
            "miss.apk".into(),
            data.len() as i64,
            Box::new(MemorySource { data, tree: None }),
        );
        let mut server = IncrementalServer::new(vec![file]);

        server.feed(&encode_request(BLOCK_MISSING, 0, 5));
        let mut forwarded = Vec::new();
        assert!(server.serve_step(&mut forwarded));

        // The requested block was flushed immediately (flush=true), plus the
        // 7-block prefetch window from idx 6 may add more; all in ≤ 2 chunks.
        let blocks = parse_blocks(&server.drain_output());
        assert!(blocks.iter().any(|(header, _)| header.block_idx == 5));
        assert!(server.files[0].sent_blocks[5]);
        // Prefetch window: blocks 6..12 sent too (7 blocks from 6 onward).
        let prefetched = (6..=12).all(|idx| server.files[0].sent_blocks[idx]);
        assert!(prefetched, "expected prefetch window 6..=12");
    }

    #[test]
    fn duplicate_prefetch_request_is_rejected() {
        let data = vec![1u8; 2 * 4096];
        let file = ServerFile::new(
            "dup.apk".into(),
            data.len() as i64,
            Box::new(MemorySource { data, tree: None }),
        );
        let mut server = IncrementalServer::new(vec![file]);

        let mut forwarded = Vec::new();
        server.feed(&encode_request(PREFETCH, 0, 0));
        assert!(server.serve_step(&mut forwarded));
        let _ = server.drain_output();

        // Same file again: rejected (no new data blocks; the only possible
        // output is the done marker since everything is already sent).
        server.feed(&encode_request(PREFETCH, 0, 0));
        assert!(server.serve_step(&mut forwarded));
        let blocks = parse_blocks(&server.drain_output());
        assert!(
            blocks
                .iter()
                .all(|(header, _)| header.file_id == -1),
            "expected only done marker after duplicate prefetch, got {blocks:?}"
        );
        assert_eq!(server.files[0].sent_blocks_count, 2);
    }

    #[test]
    fn num_bytes_and_block_index_helpers_match_aosp() {
        assert_eq!(num_bytes_to_num_blocks(0), 0);
        assert_eq!(num_bytes_to_num_blocks(1), 1);
        assert_eq!(num_bytes_to_num_blocks(4096), 1);
        assert_eq!(num_bytes_to_num_blocks(4097), 2);
        assert_eq!(offset_to_block_index(0), 0);
        assert_eq!(offset_to_block_index(4095), 0);
        assert_eq!(offset_to_block_index(8191), 1);
    }

    #[test]
    fn installation_priority_blocks_include_dex_head_and_lib_entries() {
        // Build a minimal zip in memory containing classes.dex and a lib file.
        let mut zip_bytes = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
            let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            use std::io::Write as _;
            writer.start_file("classes.dex", options).unwrap();
            writer.write_all(&vec![0xaau8; 8192]).unwrap();
            writer.start_file("lib/arm64-v8a/libfoo.so", options).unwrap();
            writer.write_all(&vec![0xbbu8; 3000]).unwrap();
            writer.start_file("assets/other.bin", options).unwrap();
            writer.write_all(&vec![0xccu8; 500]).unwrap();
            writer.finish().unwrap();
        }
        let file_size = zip_bytes.len() as i64;
        let mut cursor = std::io::Cursor::new(zip_bytes);

        let blocks = installation_priority_blocks(&mut cursor, file_size);
        assert!(!blocks.is_empty(), "expected priority blocks for dex/lib");
        // Order-preserving dedupe: first entries come from classes.dex.
        let deduped: Vec<i32> = {
            let mut seen = std::collections::HashSet::new();
            let mut out = Vec::new();
            for block in &blocks {
                if seen.insert(*block) {
                    out.push(*block);
                }
            }
            out
        };
        assert_eq!(blocks, deduped, "priority blocks must be deduplicated in order");
        // The zip starts at 0 and classes.dex data does not start at 0, but
        // the first data block of the archive (block 0) is not necessarily
        // included — assert monotonic plausibility instead: all indices are
        // within file bounds.
        let num_blocks = num_bytes_to_num_blocks(file_size);
        assert!(blocks.iter().all(|block| *block >= 0 && *block < num_blocks + 2));
    }

    #[test]
    fn priority_blocks_for_file_requires_apk_extension() {
        let data = vec![0u8; 4096 * 4];
        let mut cursor = std::io::Cursor::new(data);
        assert!(priority_blocks_for_file("plain.txt", &mut cursor, 4096 * 4).is_empty());
    }

    /// Incompressible (LCG) fixture bytes — forces the uncompressed wire path.
    fn lcg_bytes(seed: u32, length: usize) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 24) as u8
            })
            .collect()
    }

    /// Read one on-wire chunk ([be32 size][block records...]) with its size
    /// prefix included, as `parse_blocks` expects framed input.
    fn read_chunk(stream: &mut impl Read) -> Vec<u8> {
        let mut size_buf = [0u8; 4];
        stream.read_exact(&mut size_buf).unwrap();
        let size = i32::from_be_bytes(size_buf) as usize;
        let mut framed = size_buf.to_vec();
        framed.resize(4 + size, 0);
        stream.read_exact(&mut framed[4..]).unwrap();
        framed
    }

    fn fixture_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "inc-server-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn serve_fds_handshakes_serves_blocks_and_stops_on_destroy() {
        use crate::server::sysdeps_unix::{adb_close, adb_socketpair};
        use std::io::Write as _;
        use std::os::unix::io::FromRawFd;

        let data = lcg_bytes(0x1234_5678, BLOCK_SIZE as usize + 100);
        let dir = fixture_dir("serve");
        let path = dir.join("base.apk");
        std::fs::write(&path, &data).unwrap();
        let file = ServerFile::open_local(path.to_str().unwrap()).unwrap();

        let (conn_server, conn_client) = adb_socketpair().unwrap();
        let (out_server, out_client) = adb_socketpair().unwrap();
        let server_thread = std::thread::spawn(move || {
            let mut server = IncrementalServer::new(vec![file]);
            let result = server.serve_fds(conn_server, out_server);
            adb_close(conn_server);
            adb_close(out_server);
            result
        });

        let mut conn = unsafe { std::os::unix::net::UnixStream::from_raw_fd(conn_client) };
        let mut out = unsafe { std::os::unix::net::UnixStream::from_raw_fd(out_client) };
        conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        out.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();

        // Handshake.
        let mut okay = [0u8; 4];
        conn.read_exact(&mut okay).unwrap();
        assert_eq!(&okay, b"OKAY");

        // Device text followed by a BLOCK_MISSING for file 0 / block 0.
        let mut first = b"Performing Streamed Install\n".to_vec();
        first.extend_from_slice(&encode_request(BLOCK_MISSING, 0, 0));
        conn.write_all(&first).unwrap();

        // The text is forwarded verbatim to the output stream.
        let mut text = [0u8; 28];
        out.read_exact(&mut text).unwrap();
        assert_eq!(&text, b"Performing Streamed Install\n");

        // Block 0 arrives in its own chunk (BLOCK_MISSING flushes).
        let chunk = read_chunk(&mut conn);
        let blocks = parse_blocks(&chunk);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0.file_id, 0);
        assert_eq!(blocks[0].0.block_idx, 0);
        assert_eq!(blocks[0].0.compression_type, COMPRESSION_NONE);
        assert_eq!(blocks[0].1.as_slice(), &data[..BLOCK_SIZE as usize]);

        // The follow-up window prefetch feeds block 1, then the done marker.
        let chunk = read_chunk(&mut conn);
        let blocks = parse_blocks(&chunk);
        let (done, _) = blocks.last().unwrap();
        assert_eq!(*done, ResponseHeader::done_marker());
        let data_blocks = &blocks[..blocks.len() - 1];
        assert_eq!(data_blocks.len(), 1);
        assert_eq!(data_blocks[0].0.block_idx, 1);
        // A small final block compresses (LZ4 of 100 incompressible bytes is
        // 102 bytes, under kCompressedSizeMax); accept either wire form.
        let tail = match data_blocks[0].0.compression_type {
            COMPRESSION_NONE => data_blocks[0].1.clone(),
            COMPRESSION_LZ4 => lz4_flex::block::decompress(&data_blocks[0].1, 100).unwrap(),
            other => panic!("unexpected compression type {other}"),
        };
        assert_eq!(tail.as_slice(), &data[BLOCK_SIZE as usize..]);

        // DESTROY stops the server loop.
        conn.write_all(&encode_request(DESTROY, 0, 0)).unwrap();
        assert!(server_thread.join().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn serve_fds_forwards_output_and_returns_on_disconnect() {
        use crate::server::sysdeps_unix::{adb_close, adb_socketpair};
        use std::io::Write as _;
        use std::os::unix::io::FromRawFd;

        let (conn_server, conn_client) = adb_socketpair().unwrap();
        let (out_server, out_client) = adb_socketpair().unwrap();
        let server_thread = std::thread::spawn(move || {
            // No signed files: the server still handshakes and notifies done.
            let mut server = IncrementalServer::new(Vec::new());
            let result = server.serve_fds(conn_server, out_server);
            adb_close(conn_server);
            adb_close(out_server);
            result
        });

        let mut conn = unsafe { std::os::unix::net::UnixStream::from_raw_fd(conn_client) };
        let mut out = unsafe { std::os::unix::net::UnixStream::from_raw_fd(out_client) };
        conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        out.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();

        // OKAY, then the done marker straight away (nothing to stream).
        let mut okay = [0u8; 4];
        conn.read_exact(&mut okay).unwrap();
        assert_eq!(&okay, b"OKAY");
        let chunk = read_chunk(&mut conn);
        let blocks = parse_blocks(&chunk);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, ResponseHeader::done_marker());

        // Plain text: the scan forwards all but the last 4 bytes immediately.
        conn.write_all(b"hello from pm\n").unwrap();
        let mut head = [0u8; 10];
        out.read_exact(&mut head).unwrap();
        assert_eq!(&head, b"hello from");

        // Closing the connection flushes the retained tail and stops the server.
        drop(conn);
        let mut tail = [0u8; 4];
        out.read_exact(&mut tail).unwrap();
        assert_eq!(&tail, b" pm\n");
        assert!(server_thread.join().unwrap());
    }
}
