/* bonded_ffi_desktop.h — plain C-ABI surface for desktop shells (4.95).
 *
 * This header is the calling convention for Swift (macOS
 * PacketTunnelProvider) and C++ (Windows UWP plugin). It wraps the
 * same Rust session core the Android JNI layer uses, so the desktop
 * shells get the full session: transports, traffic modes, per-path
 * grades, and peer sharing (day one — mDNS discovery, relay
 * dial-back, per-peer relayed counters).
 *
 * Link against the bonded-ffi cdylib (libbonded_ffi.so / .dylib /
 * .dll) or staticlib. The FFI version is reported by
 * bonded_ffi_api_version() (currently 1); the C surface below is
 * part of that version.
 *
 * Conventions:
 *  - Every function returns an int status: 0 is success, negative
 *    is one of the BONDED_ERR_* codes below. Details live in the
 *    last-error string (bonded_session_last_error).
 *  - String outputs use caller-provided buffers. Pass out == NULL
 *    or out_len == 0 to query the required length (returned as a
 *    positive byte count, excluding the NUL); pass a big enough
 *    buffer to receive the string plus its NUL. A buffer that is
 *    too small returns BONDED_ERR_BUFFER_TOO_SMALL and nothing is
 *    written.
 *  - bonded_tun_poll_inbound returns 0 when the inbound queue is
 *    empty (not an error) and leaves an oversized packet queued
 *    when the caller's buffer is too small.
 *  - The session is process-global and single: starting a new
 *    session stops any running one. The session calls are not
 *    thread-safe against each other — serialize them from one
 *    thread, or hold your own lock. (Packet I/O may run on a
 *    different thread from the session controls.)
 *  - Peer sharing is exposed through the session config
 *    (peerShare* keys at start) and the snapshot JSON
 *    (relayedPeers per-peer counters, paths[].peerId for peer
 *    transports). There is no separate discovery API: discovery
 *    is mDNS-driven inside the session, and the dial-back /
 *    introduction flow is server-driven — the snapshot is where
 *    the shell reads the result.
 */

#ifndef BONDED_FFI_DESKTOP_H
#define BONDED_FFI_DESKTOP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes (0 is success; negative is an error). */
#define BONDED_OK 0
#define BONDED_ERR_NO_SESSION -1       /* no session is running */
#define BONDED_ERR_NULL_POINTER -2     /* a required pointer was NULL */
#define BONDED_ERR_INVALID_UTF8 -3     /* a C string was not valid UTF-8 */
#define BONDED_ERR_BUFFER_TOO_SMALL -4 /* output buffer too small; nothing written */
#define BONDED_ERR_OPERATION_FAILED -5 /* see bonded_session_last_error */
#define BONDED_ERR_UNSUPPORTED -6      /* not supported on this platform */

/* FFI version (currently 1). The C surface below is part of it. */
int bonded_ffi_api_version(void);

/* --- Session lifecycle -------------------------------------------------- */

/* Start a session from one JSON config object. Stops any running
 * session first. Keys (all strings unless noted):
 *   serverAddress            (required) e.g. "1.2.3.4:8443"
 *   resolvedServerAddress    optional pre-resolved host:port ("" = resolve)
 *   serverPublicKey          (required) base64 server identity key
 *   protocols                comma list, default "h3,wireguard,wss"
 *   pathCount                number, default 1
 *   bindAddresses            array of bind-address strings, default []
 *   cellularBindAddresses    array of cellular bind-address strings, default []
 *   peerShareEnabled         bool, default false — provide uplinks to peers
 *   peerShareBindAddress     bind address for the peer listener ("" = any)
 *   peerShareAdvertiseIp     IP to advertise to peers ("" = auto)
 *   peerShareMaxConsumers    number, default 4
 *   peerShareRelayBandwidthKbps number, default 0 (unlimited)
 *   diagnosticsUploadEnabled bool, default false
 *   diagnosticsUploadPeriodSecs number, default 900
 *   appVersionCode           number, default 0 (diagnostics tag)
 *   storageDir               (required) writable dir for keys/state
 *   batterySaver             bool, default false
 *   trafficRules             object (traffic-mode rule table), default {}
 * Returns BONDED_OK or a negative error code.
 */
int bonded_session_start(const char *config_json);

/* Stop the running session, if any. Always returns BONDED_OK
 * (stopping with no session running is a no-op). */
int bonded_session_stop(void);

/* Write the session snapshot JSON into the caller's buffer (see the
 * sizing convention above). Keys include: state, serverAddress,
 * activeTransport, transportCount, peerRelayCount, outboundPackets,
 * inboundPackets, outboundBytes, inboundBytes, relayedUpBytes,
 * relayedDownBytes, relayedPeers (array of {peerId, upBytes,
 * downBytes} — one row per peer this device is providing for),
 * heartbeatPingsSent, supervisorRedialAttempts, relayTasksStarted,
 * relayTasksEnded, connectedAtMs, lastError, peerShareError,
 * interception, and paths (array; each entry has a peerId when it
 * is a peer transport). Returns the bytes written, or
 * BONDED_ERR_NO_SESSION / BONDED_ERR_BUFFER_TOO_SMALL.
 */
int bonded_session_snapshot(char *out, size_t out_len);

/* Write the last error string into the caller's buffer. Writes an
 * empty string (and returns 0) when there is no recorded error. */
int bonded_session_last_error(char *out, size_t out_len);

/* --- Pairing ------------------------------------------------------------ */

/* Redeem an invite token against the server (pairing). The server
 * address and public key must match the server that minted the
 * token. Returns BONDED_OK or a negative error code. */
int bonded_redeem_invite_token(const char *server_address,
                               const char *server_public_key,
                               const char *invite_token,
                               const char *storage_dir);

/* Mint a bound invite for another device (QR-pairing flow),
 * authenticated by this device's existing pairing. Writes the
 * invite token into the caller's buffer. Returns the bytes
 * written, or a negative error code. */
int bonded_mint_invite_token(const char *server_address,
                             const char *server_public_key,
                             const char *storage_dir,
                             const char *target_device_key,
                             char *out,
                             size_t out_len);

/* This device's public key, creating the keypair if this is the
 * first run. Writes the base64 key into the caller's buffer.
 * Returns the bytes written, or a negative error code. */
int bonded_device_public_key(const char *storage_dir,
                             char *out,
                             size_t out_len);

/* --- Packet I/O --------------------------------------------------------- */

/* Install (or clear, with fd < 0) the TUN fd the worker writes
 * inbound packets to directly. Unix-only: on Windows this returns
 * BONDED_ERR_UNSUPPORTED and inbound packets always go through the
 * poll queue. Shells that move packets through their own channel
 * (the macOS PacketTunnelProvider's NEPacketTunnelFlow, the UWP
 * plugin's channel) just use bonded_tun_handle_outbound /
 * bonded_tun_poll_inbound and never call this. */
int bonded_tun_set_fd(int fd);

/* Feed one outbound packet (as read from the platform tunnel) into
 * the session. Returns BONDED_OK, or BONDED_ERR_OPERATION_FAILED
 * when no session is running (or its channel is closed). */
int bonded_tun_handle_outbound(const uint8_t *packet, size_t len);

/* Drain one inbound packet (to be written to the platform tunnel)
 * into the caller's buffer. Returns the bytes written, 0 when the
 * inbound queue is empty, BONDED_ERR_NO_SESSION when no session is
 * running, or BONDED_ERR_BUFFER_TOO_SMALL when the front packet
 * does not fit — in that case the packet stays queued. */
int bonded_tun_poll_inbound(uint8_t *out, size_t out_len);

/* --- Path controls ------------------------------------------------------ */

/* Pause (paused != 0) or resume one direct path. Returns
 * BONDED_OK or BONDED_ERR_NO_SESSION. */
int bonded_path_pause(uint32_t path_index, int paused);

/* Tear one direct path's transport down and let the path
 * supervisor re-dial it in place. Returns BONDED_OK or
 * BONDED_ERR_NO_SESSION. */
int bonded_path_reset(uint32_t path_index);

/* Hand the live worker a new bind-address list (an interface
 * appeared or vanished) without restarting the session. Both
 * arguments are JSON arrays of address strings. Returns
 * BONDED_OK or BONDED_ERR_NO_SESSION. */
int bonded_paths_update(const char *bind_addresses_json,
                        const char *cellular_bind_addresses_json);

/* Hand the running worker a new traffic-rules table (JSON)
 * without restarting the session. Always returns BONDED_OK — a
 * malformed table falls back to the default engine. */
int bonded_traffic_rules_update(const char *traffic_rules_json);

/* Hand the running worker the current per-transport grades (JSON
 * array, one entry per transport vec index). Always returns
 * BONDED_OK — malformed JSON clears the grades. */
int bonded_path_grades_update(const char *path_grades_json);

/* Tell the worker whether the display is interactive (screen
 * on/off). Returns BONDED_OK or BONDED_ERR_NO_SESSION. */
int bonded_display_interactive(int interactive);

/* Tell the worker whether the device is in idle mode (Doze).
 * Returns BONDED_OK or BONDED_ERR_NO_SESSION. */
int bonded_device_idle_mode(int idle);

#ifdef __cplusplus
}
#endif

#endif /* BONDED_FFI_DESKTOP_H */
