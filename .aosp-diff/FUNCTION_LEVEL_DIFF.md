# AOSP 26Q2 vs adb-fastboot-rs 函数级差分报告

基线: AOSP ~/adb @ 9084198a (26Q2-release) | Rust: f900d3c (双线合并后)

Android.bp 权威分母: 67 host 侧 .cpp / 456 函数定义。名字级差分 412；
按功能域归类后分为 命名差分（语义等价、API 名不同）/ 部分实现 / 功能真空。

## 功能域判定表

| 功能域 | AOSP fns | Rust 现状 | 判定 |
|---|---|---|---|
| fdevent 事件循环 | 16 | fdevent.rs 存在（timeout 测试过），API 名不同 | 命名差分+部分(ambient/run_on_looper) |
| sockets asocket 状态机 | 15 | smart_socket.rs Local/Remote/Smart enum 已实现核心 | 命名差分（enum 替代 vtable） |
| transport 注册表 | 12 | server/transport.rs+models.rs TransportRegistry 已实现 | 命名差分 |
| mdns 后端 | 8 | parser 已实现(mdns.rs 22fns)；openscreen 后端真空 | 功能真空→建依赖库 |
| incremental/fastdeploy | 48 | incremental.rs 仅 4 fns 骨架 | 功能真空(大块)→protobuf 依赖 |
| adb_install 安装分支 | 21 | adb_install.rs 7 fns(pm install shell 路径) | 部分实现(streamed/multi/abb_exec/apex 缺) |
| usb hotplug | 18 | transport_usb.rs+usb_android.rs usbfs 直连+watcher 真机验证过 | 命名差分 |
| adb_client server 协议 | 20 | AdbServerTransport+server_cmds/host_command 核心 | 命名差分 |
| console 模拟器控制台 | 5 | console.rs parse 完整(18fns)；connect/auth/send 网络层缺 | 部分实现(网络层缺) |
| pairing_connection C API | 8 | pairing_connection.rs/pairing_server.rs 原生 API | 命名差分 |
| sysdeps 网络 | 7 | sysdeps_posix_network.rs 有核心；keepalive/peek/launch 缺 | 部分实现 |
| listeners forward | 10 | forward.rs 有 server forward；remove_all/format 缺 | 部分实现 |
| auth inotify+TLS 证书链 | 6 | key.rs 有 load_persistent/AuthResponder；inotify/TLS 证书链缺 | 部分实现 |
| errno wire 映射 | 4 | 无 | 功能真空(小,host 侧价值低) |
| trace init | 4 | adb_trace.rs 有部分 | 部分实现 |
| emulator 扫描器 | 12 | transport_emulator.rs 9 fns(探测层) | 部分实现 |
| mdns C bridge(adbmdns) | 4 | mdns.rs parser 层 | 功能真空(依赖 openscreen) |

## 汇总: 命名差分 6 域 / 部分实现 7 域 / 功能真空 4 域

- 命名差分: fdevent 事件循环, sockets asocket 状态机, transport 注册表, usb hotplug, adb_client server 协议, pairing_connection C API
- 部分实现: adb_install 安装分支, console 模拟器控制台, sysdeps 网络, listeners forward, auth inotify+TLS 证书链, trace init, emulator 扫描器
- 功能真空: mdns 后端, incremental/fastdeploy, errno wire 映射, mdns C bridge(adbmdns)

## 施工结论

1. 核心链路（smart-socket/transport/sockets、client shell/sync、crypto/pairing_auth）为命名差分，
   Rust 用 enum/模块树实现 AOSP vtable/单体语义，不需逐名补。
2. 真空集中: mDNS 后端(openscreen-discovery 等价)、incremental/fastdeploy 管线(protobuf)、
   install streamed/multi-package 分支、console 网络层、auth inotify、sysdeps 小函数。
3. 「创建依赖库」候选: (a) mDNS 后端 crate（openscreen-discovery 等价，独立可测）;
   (b) incremental 管线 crate（需 vendored protobuf 生成代码，或 prost 轻依赖）。
4. 建议顺序: 先真空里对可用性影响最大且可独立验收的 console 网络层(小)、sysdeps 小函数(小)、
   再 mDNS 后端(中)，最后 incremental(大,依赖 protobuf)。install 分支与 auth inotify 居中。
## 附录: 逐文件 × 逐函数明细

| AOSP 文件 | Rust 位置 | AOSP fns | 全库同名 | 不同名 |
|---|---|---:|---:|---:|
| adb.cpp | server: runner.rs/handler.rs | 33 | 1 | 32 |
| adb_io.cpp | server: adb_io.rs | 0 | 0 | 0 |
| adb_listeners.cpp | server: forward.rs | 10 | 0 | 10 |
| adb_mdns.cpp | server: adb_mdns.rs | 2 | 0 | 2 |
| adb_trace.cpp | server: adb_trace.rs | 6 | 2 | 4 |
| adb_unique_fd.cpp | server: transport_fd.rs | 0 | 0 | 0 |
| adb_utils.cpp | server adb_utils.rs / protocol adb_utils.rs | 13 | 12 | 1 |
| apacket_reader.cpp | server: apacket_reader.rs | 0 | 0 | 0 |
| fdevent/fdevent.cpp | server: fdevent.rs | 17 | 0 | 17 |
| fdevent/fdevent_epoll.cpp | server: fdevent.rs | 3 | 0 | 3 |
| services.cpp | server: services.rs | 9 | 2 | 7 |
| sockets.cpp | server: smart_socket.rs+bridge.rs | 30 | 1 | 29 |
| socket_spec.cpp | server: socket_spec.rs | 8 | 7 | 1 |
| sysdeps/errno.cpp | server: adb_utils.rs | 4 | 0 | 4 |
| sysdeps_unix.cpp | server: sysdeps_unix.rs | 4 | 0 | 4 |
| sysdeps/posix/network.cpp | server: sysdeps_posix_network.rs | 8 | 0 | 8 |
| transport.cpp | server: transport.rs+models.rs | 42 | 1 | 41 |
| transport_fd.cpp | server: transport_fd.rs | 0 | 0 | 0 |
| types.cpp | server: types.rs | 0 | 0 | 0 |
| client/adb_client.cpp | client: server_cmds.rs+host_command.rs | 19 | 0 | 19 |
| client/adb_install.cpp | client: adb_install.rs | 21 | 0 | 21 |
| client/adb_wifi.cpp | client: adb_wifi.rs | 1 | 0 | 1 |
| client/adbmdns/adbmdns.cpp | client: mdns.rs | 4 | 0 | 4 |
| client/auth.cpp | protocol: crypto/key.rs | 23 | 4 | 19 |
| client/bugreport.cpp | client: bugreport.rs | 0 | 0 | 0 |
| client/commandline.cpp | cli: main_adb.rs + client shell/exec_out/file_sync | 36 | 0 | 36 |
| client/console.cpp | client: console.rs | 4 | 0 | 4 |
| client/detach.cpp | client: detach.rs | 0 | 0 | 0 |
| client/discovered_services.cpp | client: discovered_services.rs | 1 | 0 | 1 |
| client/fastdeploy.cpp | client: incremental.rs | 12 | 0 | 12 |
| client/file_sync_client.cpp | client: file_sync.rs | 21 | 1 | 20 |
| client/incremental.cpp | client: incremental.rs | 15 | 0 | 15 |
| client/incremental_server.cpp | client: incremental.rs | 7 | 0 | 7 |
| client/incremental_utils.cpp | client: incremental.rs | 10 | 0 | 10 |
| client/line_printer.cpp | client: line_printer.rs | 0 | 0 | 0 |
| client/main.cpp | cli: main_adb.rs | 6 | 1 | 5 |
| client/mdns_tracker.cpp | client: mdns.rs | 7 | 0 | 7 |
| client/mdns_utils.cpp | client: mdns.rs | 3 | 0 | 3 |
| client/pairing/pairing_client.cpp | protocol: pairing.rs | 1 | 0 | 1 |
| client/transport_emulator.cpp | client: transport_emulator.rs | 13 | 1 | 12 |
| client/transport_mdns.cpp | client: transport_mdns.rs | 6 | 0 | 6 |
| client/transport_usb.cpp | client: transport_usb.rs | 4 | 1 | 3 |
| client/usb_linux.cpp | client: transport_usb.rs + protocol usb_android.rs | 18 | 0 | 18 |
| client/usb_linux_netlink.cpp | client: transport_usb.rs | 0 | 0 | 0 |
| client/usb_libusb.cpp | client: usb_libusb.rs | 1 | 0 | 1 |
| shell_service_protocol.cpp | protocol: shell_v2.rs | 0 | 0 | 0 |
| crypto/key.cpp | protocol: crypto/key.rs | 0 | 0 | 0 |
| crypto/rsa_2048_key.cpp | protocol: crypto/rsa_2048_key.rs | 0 | 0 | 0 |
| crypto/x509_generator.cpp | protocol: crypto/x509_generator.rs | 1 | 0 | 1 |
| tls/adb_ca_list.cpp | protocol: tls/adb_ca_list.rs | 0 | 0 | 0 |
| tls/tls_connection.cpp | protocol: tls/tls_connection.rs | 0 | 0 | 0 |
| pairing_auth/pairing_auth.cpp | protocol: pairing_auth/ | 10 | 10 | 0 |
| pairing_connection/pairing_connection.cpp | protocol: pairing_connection/pairing_connection.rs | 6 | 0 | 6 |
| pairing_connection/pairing_server.cpp | protocol: pairing_connection/pairing_server.rs | 9 | 0 | 9 |

## 附录: 各文件缺名函数全集（供施工逐个对号）

### adb.cpp → server: runner.rs/handler.rs
- `_create_anonymous_pipe`, `_make_handle_noninheritable`, `_redirect_pipe_thread`, `_redirect_stderr_thread`, `_redirect_stdout_thread`, `_try_make_handle_noninheritable`, `adb_notify_device_scan_complete`, `adb_set_reject_kill_server`, `adb_version`, `adb_wait_for_device_initialization`, `calculate_apacket_checksum`, `command_to_string`, `get_apacket`, `get_connection_string`, `handle_forward_request`, `handle_host_request`, `handle_mdns_request`, `handle_new_connection`, `handle_offline`, `handle_online`, `handle_packet`, `is_one_device_mandatory`, `is_usb_enabled`, `launch_server`, `parse_banner`, `print_packet`, `put_apacket`, `send_connect`, `send_ready`, `send_tls_request`, `to_string`, `update_transport_status`

### adb_listeners.cpp → server: forward.rs
- `alistener`, `close_smartsockets`, `enable_server_sockets`, `format_listeners`, `install_listener`, `listener_disconnect`, `listener_event_func`, `remove_all_listeners`, `remove_listener`, `ss_listener_event_func`

### adb_mdns.cpp → server: adb_mdns.rs
- `config_auto_connect_services`, `for_each`

### adb_trace.cpp → server: adb_trace.rs
- `adb_trace_init`, `get_log_file_name`, `get_trace_setting`, `setup_trace_mask`

### adb_utils.cpp → server adb_utils.rs / protocol adb_utils.rs
- `directory_exists`

### fdevent/fdevent.cpp → server: fdevent.rs
- `dump_fde`, `fdevent_add`, `fdevent_create`, `fdevent_create_context`, `fdevent_del`, `fdevent_destroy`, `fdevent_get_ambient`, `fdevent_installed_count`, `fdevent_loop`, `fdevent_release`, `fdevent_reset`, `fdevent_run_on_looper`, `fdevent_set`, `fdevent_set_timeout`, `fdevent_terminate_loop`, `g_ambient_fdevent_context`, `invoke_fde`

### fdevent/fdevent_epoll.cpp → server: fdevent.rs
- `calculate_epoll_event`, `fdevent_context_epoll`, `fdevent_interrupt`

### services.cpp → server: services.rs
- `connect_emulator`, `connect_service`, `list_mdns_known_hosts`, `pair_service`, `service_bootstrap_func`, `service_to_fd`, `wait_service`

### sockets.cpp → server: smart_socket.rs+bridge.rs
- `close_all_sockets`, `connect_to_smartsocket`, `create_local_service_socket`, `create_local_socket`, `create_remote_socket`, `create_smart_socket`, `deferred_close`, `find_local_socket`, `install_local_socket`, `local_socket_ack`, `local_socket_close`, `local_socket_close_notify`, `local_socket_destroy`, `local_socket_enqueue`, `local_socket_event_func`, `local_socket_flush_incoming`, `local_socket_flush_outgoing`, `local_socket_ready`, `local_socket_ready_notify`, `parse_host_service`, `remote_socket_close`, `remote_socket_enqueue`, `remote_socket_ready`, `remote_socket_shutdown`, `remove_socket`, `smart_socket_close`, `smart_socket_enqueue`, `smart_socket_ready`, `unhex`

### socket_spec.cpp → server: socket_spec.rs
- `check_adb_vsock_cid_port`

### sysdeps/errno.cpp → server: adb_utils.rs
- `errno_from_wire`, `errno_to_wire`, `generate_host_to_wire`, `generate_wire_to_host`

### sysdeps_unix.cpp → server: sysdeps_unix.rs
- `adb_launch_process`, `disable_close_on_exec`, `network_peek`, `set_tcp_keepalive`

### sysdeps/posix/network.cpp → server: sysdeps_posix_network.rs
- `_network_loopback_client`, `_network_loopback_server`, `loopback_addr4`, `loopback_addr6`, `network_connect`, `network_loopback_client`, `network_loopback_server`, `set_error`

### transport.cpp → server: transport.rs+models.rs
- `acquire_one_transport`, `append_transport`, `append_transport_info`, `burst_mode_enabled`, `call_once`, `check_header`, `close_usb_devices`, `contains`, `create_device_tracker`, `device_tracker_close`, `device_tracker_enqueue`, `device_tracker_ready`, `device_tracker_remove`, `device_tracker_send`, `fdevent_register_transport`, `fdevent_unregister_transport`, `features`, `find_transport`, `init_reconnect_handler`, `iterate_transports`, `kick_all_tcp_devices`, `kick_all_tcp_tls_transports`, `kick_all_transports`, `kick_all_transports_by_auth_key`, `list_transports`, `qual_match`, `register_libusb_transport`, `register_socket_transport`, `register_transport`, `register_usb_transport`, `remove_transport`, `sanitize`, `send_packet`, `supported_features`, `transport_destroy`, `transport_get_one_device`, `transport_server_owns_device`, `transport_set_one_device`, `unregister_usb_transport`, `update_transports`, `validate_transport_list`

### client/adb_client.cpp → client: server_cmds.rs+host_command.rs
- `__adb_check_server_version`, `_adb_connect`, `adb_check_server_version`, `adb_command`, `adb_connect`, `adb_get_feature_set`, `adb_get_server_executable_path`, `adb_get_transport`, `adb_kill_server`, `adb_query`, `adb_set_one_device`, `adb_set_socket_spec`, `adb_set_transport`, `adb_status`, `call_once`, `error_exit`, `format_host_command`, `perror_exit`, `switch_socket_transport`

### client/adb_install.cpp → client: adb_install.rs
- `best_install_mode`, `calculate_install_mode`, `delete_device_file`, `install_app`, `install_app_incremental`, `install_app_legacy`, `install_app_streamed`, `install_multi_package`, `install_multiple_app`, `install_multiple_app_streamed`, `is_abb_exec_supported`, `is_apex_supported`, `ms_between`, `parse_fast_deploy_mode`, `parse_install_mode`, `pm_command`, `read_status_line`, `send_command`, `uninstall_app`, `uninstall_app_legacy`, `uninstall_app_streamed`

### client/adb_wifi.cpp → client: adb_wifi.rs
- `adb_wifi_pair_device`

### client/adbmdns/adbmdns.cpp → client: mdns.rs
- `events_cb`, `format`, `logger_cb`, `update_to_state`

### client/auth.cpp → protocol: crypto/key.rs
- `adb_auth_get_private_keys`, `adb_auth_get_user_privkey`, `adb_auth_get_userkey`, `adb_auth_init`, `adb_auth_inotify_init`, `adb_auth_inotify_update`, `adb_auth_keygen`, `adb_auth_pubkey`, `adb_auth_sign`, `adb_auth_tls_handshake`, `adb_tls_set_certificate`, `hash_key`, `load_key`, `load_keys`, `pubkey_from_privkey`, `read_key_file`, `send_auth_publickey`, `send_auth_response`, `thread`

### client/commandline.cpp → cli: main_adb.rs + client shell/exec_out/file_sync
- `_is_valid_ack_reply_fd`, `_is_valid_os_fd`, `adb_abb`, `adb_commandline`, `adb_connect_command`, `adb_connect_command_bidirectional`, `adb_get_feature_set_or_die`, `adb_query_command`, `adb_root`, `adb_shell`, `adb_shell_noinput`, `adb_sideload_install`, `adb_sideload_legacy`, `adb_wipe_devices`, `backup`, `copy_to_file`, `forward_dest_is_featured`, `help`, `logcat`, `parse_compression_type`, `parse_push_pull_args`, `process_remount_or_verity_service`, `product_file`, `read_and_dump`, `read_and_dump_protocol`, `restore`, `send_shell_command`, `send_window_size_change`, `stdin_raw_init`, `stdin_raw_restore`, `stdin_read_thread_loop`, `stdinout_raw_epilogue`, `stdinout_raw_prologue`, `thread`, `wait_for_device`, `write_zeros`

### client/console.cpp → client: console.rs
- `adb_construct_auth_command`, `adb_get_emulator_console_port`, `adb_send_emulator_command`, `connect_to_console`

### client/discovered_services.cpp → client: discovered_services.rs
- `fq_name`

### client/fastdeploy.cpp → client: incremental.rs
- `apply_patch_on_device`, `create_patch`, `deploy_agent`, `extract_metadata`, `fastdeploy_set_agent_update_strategy`, `get_device_api_level`, `get_package_name_from_apk`, `get_string_from_utf16`, `install_patch`, `push_to_device`, `stream_patch`, `update_agent_if_necessary`

### client/file_sync_client.cpp → client: file_sync.rs
- `copy_local_dir_remote`, `copy_remote_dir_local`, `do_sync_ls`, `do_sync_pull`, `do_sync_push`, `do_sync_sync`, `ensure_trailing_separators`, `is_root_dir`, `local_build_list`, `remote_build_list`, `should_pull_file`, `should_push_file`, `sync_ls`, `sync_lstat`, `sync_recv`, `sync_recv_v1`, `sync_recv_v2`, `sync_send`, `sync_stat`, `sync_stat_fallback`

### client/incremental.cpp → client: incremental.rs
- `build_database`, `connect_and_send_database`, `encode_signature`, `fd`, `file_id`, `install`, `open_and_get_size`, `path`, `read_signature`, `requires_v4_signature`, `send_unsigned_files`, `should_use_incremental_by_default`, `start_inc_server_and_stream_signed_files`, `validate_signature`, `wait_for_installation`

### client/incremental_server.cpp → client: incremental.rs
- `all_of`, `constexpr`, `done`, `erase_buffer_head`, `open_fd`, `open_signature`, `serve`

### client/incremental_utils.cpp → client: incremental.rs
- `append_bytes_with_size`, `append_int`, `read_id_sig_headers`, `read_int32`, `skip_bytes_with_size`, `skip_id_sig_headers`, `skip_int`, `unduplicate`, `verity_tree_blocks_for_file`, `verity_tree_size_for_file`

### client/main.cpp → cli: main_adb.rs
- `adb_server_cleanup`, `adb_server_main`, `intentionally_leak`, `notify_thread`, `setup_daemon_logging`

### client/mdns_tracker.cpp → client: mdns.rs
- `create_mdns_tracker`, `device_tracker_enqueue`, `list_mdns_services`, `mdns_tracker_close`, `mdns_tracker_ready`, `mdns_tracker_send`, `update_mdns_trackers`

### client/mdns_utils.cpp → client: mdns.rs
- `is_enabled`, `mdns_parse_instance_name`, `should_use_openscreen`

### client/pairing/pairing_client.cpp → protocol: pairing.rs
- `operator`

### client/transport_emulator.cpp → client: transport_emulator.rs
- `adb_local_transport_max_port_env_override`, `client_socket_thread`, `connect_emulator`, `connect_emulator_arbitrary_ports`, `find_emulator_transport_by_adb_port`, `find_emulator_transport_by_adb_port_locked`, `find_emulator_transport_by_console_port`, `init_emulator_scanner`, `init_socket_transport`, `init_socket_transport_emulator`, `init_socket_transport_tcp`, `move`

### client/transport_mdns.cpp → client: transport_mdns.rs
- `adb_secure_connect_by_service_name`, `init_mdns_transport_discovery`, `mdns_check`, `mdns_get_connect_service_info`, `mdns_get_pairing_service_info`, `mdns_list_discovered_services`

### client/transport_usb.cpp → client: transport_usb.rs
- `init_usb_transport`, `is_libusb_enabled`, `remote_read`

### client/usb_linux.cpp → client: transport_usb.rs + protocol usb_android.rs
- `contains_non_digit`, `device_poll_thread`, `is_known_device`, `process_usb_device`, `register_device`, `scan_usb_devices`, `unix_open_retry`, `usb_bulk_read`, `usb_bulk_write`, `usb_cleanup`, `usb_close`, `usb_get_max_packet_size`, `usb_init`, `usb_kick`, `usb_read`, `usb_reset`, `usb_write`, `usb_write_split`

### client/usb_libusb.cpp → client: usb_libusb.rs
- `call_once`

### crypto/x509_generator.cpp → protocol: crypto/x509_generator.rs
- `add_ext`

### pairing_connection/pairing_connection.cpp → protocol: pairing_connection/pairing_connection.rs
- `operator`, `pairing_connection_client_new`, `pairing_connection_destroy`, `pairing_connection_server_new`, `pairing_connection_start`, `string_view`

### pairing_connection/pairing_server.cpp → protocol: pairing_connection/pairing_server.rs
- `call_once`, `operator`, `pairing_server_destroy`, `pairing_server_get_port`, `pairing_server_is_feature_supported`, `pairing_server_new`, `pairing_server_new_no_cert`, `pairing_server_start`, `pairing_server_stop_listening`
