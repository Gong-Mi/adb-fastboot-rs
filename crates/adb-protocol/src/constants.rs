/// ADB Wire Protocol Command Identifiers (stored in little-endian as u32)
pub const A_SYNC: u32 = 0x434E5953; // "SYNC"
pub const A_CNXN: u32 = 0x4E584E43; // "CNXN"
pub const A_OPEN: u32 = 0x4E45504F; // "OPEN"
pub const A_OKAY: u32 = 0x59414B4F; // "OKAY"
pub const A_CLSE: u32 = 0x45534C43; // "CLSE"
pub const A_WRTE: u32 = 0x45545257; // "WRTE"
pub const A_AUTH: u32 = 0x48545541; // "AUTH"
pub const A_STLS: u32 = 0x534C5453; // "STLS"

/// ADB Version & Max Payload
pub const ADB_VERSION: u32 = 0x01000001;
pub const MAX_PAYLOAD_V1: u32 = 4096;
pub const MAX_PAYLOAD_V2: u32 = 1024 * 1024; // 1MB

/// AUTH Sub-types
pub const A_AUTH_TOKEN: u32 = 1;
pub const A_AUTH_SIGNATURE: u32 = 2;
pub const A_AUTH_RSAKEY: u32 = 3;

/// ADB Sync Protocol Command Identifiers
pub const SYNC_STAT: u32 = 0x54415453; // "STAT"
pub const SYNC_LIST: u32 = 0x5453494C; // "LIST"
pub const SYNC_SEND: u32 = 0x444E4553; // "SEND"
pub const SYNC_RECV: u32 = 0x56434552; // "RECV"
pub const SYNC_DENT: u32 = 0x544E4544; // "DENT"
pub const SYNC_DONE: u32 = 0x454E4F44; // "DONE"
pub const SYNC_DATA: u32 = 0x41544144; // "DATA"
pub const SYNC_FAIL: u32 = 0x4C494146; // "FAIL"
pub const SYNC_OKAY: u32 = 0x59414B4F; // "OKAY"

/// ADB Sync Protocol v2 Command Identifiers
pub const SYNC_STA2: u32 = 0x32415453; // "STA2" (STAT_V2)
pub const SYNC_LST2: u32 = 0x3254534C; // "LST2" (LSTAT_V2)
pub const SYNC_DENT_V2: u32 = 0x32544E44; // "DNT2" (DENT_V2)
pub const SYNC_STAT_V2: u32 = SYNC_STA2;
pub const SYNC_LSTAT_V2: u32 = SYNC_LST2;

/// sendrecv_v2 protocol
pub const SYNC_SEND_V2: u32 = 0x32444E53; // "SND2"
pub const SYNC_RECV_V2: u32 = 0x32505643; // "RCV2"
pub const SYNC_QUIT: u32 = 0x54495551;    // "QUIT"
pub const SYNC_FLAG_NONE: u32 = 0;
pub const SYNC_FLAG_BROTLI: u32 = 1;
pub const SYNC_FLAG_LZ4: u32 = 2;
pub const SYNC_FLAG_ZSTD: u32 = 4;
pub const SYNC_FLAG_DRY_RUN: u32 = 0x8000_0000;
pub const SYNC_DATA_MAX: usize = 64 * 1024;

/// Shell v2 Stream Identifiers
pub const SHELL_ID_STDIN: u8 = 0;
pub const SHELL_ID_STDOUT: u8 = 1;
pub const SHELL_ID_STDERR: u8 = 2;
pub const SHELL_ID_EXIT: u8 = 3;
pub const SHELL_ID_CLOSE_STDIN: u8 = 4;
pub const SHELL_ID_WINDOW_SIZE_CHANGE: u8 = 5;
