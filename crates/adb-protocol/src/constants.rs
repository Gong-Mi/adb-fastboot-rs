/// ADB Wire Protocol Command Identifiers (stored in little-endian as u32)
pub const A_SYNC: u32 = 0x434E5953; // "SYNC"
pub const A_CNXN: u32 = 0x4E584E43; // "CNXN"
pub const A_OPEN: u32 = 0x4E45504F; // "OPEN"
pub const A_OKAY: u32 = 0x59414B4F; // "OKAY"
pub const A_CLSE: u32 = 0x45534C43; // "CLSE"
pub const A_WRTE: u32 = 0x45545257; // "WRTE"
pub const A_AUTH: u32 = 0x48545541; // "AUTH"
pub const A_STLS: u32 = 0x534C5453; // "STLS"

/// Stream-based TLS protocol version used by AOSP ADB.
pub const A_STLS_VERSION_MIN: u32 = 0x01000000;
pub const A_STLS_VERSION: u32 = 0x01000000;

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
pub const SHELL_ID_INVALID: u8 = 255;

// ---------------------------------------------------------------------------
// ADB feature strings (AOSP transport.cpp kFeature*)
// ---------------------------------------------------------------------------

pub const FEATURE_SHELL_V2: &str = "shell_v2";
pub const FEATURE_CMD: &str = "cmd";
pub const FEATURE_STAT_V2: &str = "stat_v2";
pub const FEATURE_LS_V2: &str = "ls_v2";
pub const FEATURE_LIBUSB: &str = "libusb";
pub const FEATURE_PUSH_SYNC: &str = "push_sync";
pub const FEATURE_APEX: &str = "apex";
pub const FEATURE_FIXED_PUSH_MKDIR: &str = "fixed_push_mkdir";
pub const FEATURE_ABB: &str = "abb";
pub const FEATURE_FIXED_PUSH_SYMLINK_TIMESTAMP: &str = "fixed_push_symlink_timestamp";
pub const FEATURE_ABB_EXEC: &str = "abb_exec";
pub const FEATURE_REMOUNT_SHELL: &str = "remount_shell";
pub const FEATURE_TRACK_APP: &str = "track_app";
pub const FEATURE_SENDRECV_V2: &str = "sendrecv_v2";
pub const FEATURE_SENDRECV_V2_BROTLI: &str = "sendrecv_v2_brotli";
pub const FEATURE_SENDRECV_V2_LZ4: &str = "sendrecv_v2_lz4";
pub const FEATURE_SENDRECV_V2_ZSTD: &str = "sendrecv_v2_zstd";
pub const FEATURE_SENDRECV_V2_DRY_RUN_SEND: &str = "sendrecv_v2_dry_run_send";
pub const FEATURE_DELAYED_ACK: &str = "delayed_ack";
pub const FEATURE_OPENSCREEN_MDNS: &str = "openscreen_mdns";
pub const FEATURE_DEVICE_TRACKER_PROTO_FORMAT: &str = "devicetracker_proto_format";
pub const FEATURE_DEV_RAW: &str = "devraw";
pub const FEATURE_APP_INFO: &str = "app_info";
pub const FEATURE_SERVER_STATUS: &str = "server_status";
pub const FEATURE_TRACK_MDNS: &str = "track_mdns";
