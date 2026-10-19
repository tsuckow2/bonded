package com.bonded.bonded_app

import android.content.Context
import java.time.Instant
import org.json.JSONArray
import org.json.JSONObject

data class PairedServerRecord(
        val id: String,
        val publicAddress: String,
    val serverIdentityPublicKey: String,
        val supportedProtocols: List<String>,
    val peerShareEnabled: Boolean,
    val peerShareBindAddress: String,
    val peerShareAdvertiseIp: String,
    val peerShareMaxConsumers: Int,
    val peerShareRelayBandwidthKbps: Long,
        val pairedAt: String,
    // Last server address that DNS resolved successfully (host:port with an
    // IP literal). Session restarts that happen while the TUN is up cannot
    // resolve the hostname — DNS routes into the dead tunnel — so they fall
    // back to this. Empty until the first successful resolution.
    val lastResolvedAddress: String = "",
    // Opt-in periodic upload of the on-device diagnostic log to this
    // server, signed with the device key. Off by default.
    val diagnosticsUploadEnabled: Boolean = false,
    val diagnosticsUploadPeriodSecs: Long = 900,
) {
    val serverPublicKey: String
    get() = serverIdentityPublicKey
}

object PairedServerStore {
    private const val PREFS_NAME = "bonded.paired_servers"
    private const val KEY_RECORDS = "records"
    private const val LEGACY_KEY_DEVICE_ID = "deviceId"
    private const val LEGACY_KEY_PUBLIC_ADDRESS = "publicAddress"
    private const val LEGACY_KEY_SERVER_PUBLIC_KEY = "serverPublicKey"
    private const val KEY_SERVER_IDENTITY_PUBLIC_KEY = "serverIdentityPublicKey"
    private const val LEGACY_KEY_PAIRED_AT = "pairedAt"

    fun save(context: Context, record: PairedServerRecord) {
        val records =
            loadAll(context)
                .filterNot { it.id == record.id || it.publicAddress == record.publicAddress }
                .toMutableList()
        records.add(record)
        persist(context, records)
    }

    fun loadAll(context: Context): List<PairedServerRecord> {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val raw = prefs.getString(KEY_RECORDS, "[]") ?: "[]"
        val parsed = parseRecords(raw)
        if (parsed.isNotEmpty()) {
            return parsed
        }

        // Backward-compatibility migration path for pre-array storage.
        val legacy = parseLegacySingleRecord(prefs)
        if (legacy != null) {
            persist(context, listOf(legacy))
            return listOf(legacy)
        }

        return emptyList()
    }

    fun findById(context: Context, id: String): PairedServerRecord? {
        return selectPreferredRecord(loadAll(context), id)
    }

    fun selectPreferredRecord(
        records: List<PairedServerRecord>,
        preferredDeviceId: String? = null,
    ): PairedServerRecord? {
        val exactMatch = preferredDeviceId?.trim()?.takeIf { it.isNotEmpty() }
            ?.let { requestedId ->
                records.firstOrNull { it.id == requestedId }
            }
        if (exactMatch != null) {
            return exactMatch
        }

        return records.maxWithOrNull(compareBy<PairedServerRecord> { record ->
            runCatching { Instant.parse(record.pairedAt) }.getOrDefault(Instant.EPOCH)
        })
    }

    fun delete(context: Context, id: String) {
        val records = loadAll(context).filterNot { it.id == id }
        persist(context, records)
    }

    fun updateLastResolvedAddress(context: Context, id: String, resolvedAddress: String) {
        if (resolvedAddress.isBlank()) {
            return
        }
        val records =
            loadAll(context).map { record ->
                if (record.id == id) {
                    record.copy(lastResolvedAddress = resolvedAddress)
                } else {
                    record
                }
            }
        persist(context, records)
    }

    private fun persist(context: Context, records: List<PairedServerRecord>) {
        val array = JSONArray()
        records.forEach { record ->
            array.put(
                    JSONObject()
                            .put("id", record.id)
                            .put("publicAddress", record.publicAddress)
                            .put(KEY_SERVER_IDENTITY_PUBLIC_KEY, record.serverIdentityPublicKey)
                            .put("serverPublicKey", record.serverIdentityPublicKey)
                            .put("supportedProtocols", JSONArray(record.supportedProtocols))
                            .put("peerShareEnabled", record.peerShareEnabled)
                            .put("peerShareBindAddress", record.peerShareBindAddress)
                            .put("peerShareAdvertiseIp", record.peerShareAdvertiseIp)
                            .put("peerShareMaxConsumers", record.peerShareMaxConsumers)
                            .put("peerShareRelayBandwidthKbps", record.peerShareRelayBandwidthKbps)
                            .put("pairedAt", record.pairedAt)
                            .put("lastResolvedAddress", record.lastResolvedAddress)
                            .put("diagnosticsUploadEnabled", record.diagnosticsUploadEnabled)
                            .put("diagnosticsUploadPeriodSecs", record.diagnosticsUploadPeriodSecs),
            )
        }

        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_RECORDS, array.toString())
                .apply()
    }

    private fun parseProtocols(array: JSONArray?): List<String> {
        if (array == null) {
            return emptyList()
        }

        return buildList {
            for (index in 0 until array.length()) {
                add(array.optString(index))
            }
        }
    }

    private fun parseRecords(raw: String): List<PairedServerRecord> {
        val array =
                try {
                    JSONArray(raw)
                } catch (_: Exception) {
                    return emptyList()
                }

        return buildList {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue

                val id = item.optString("id").trim()
                val publicAddress = item.optString("publicAddress").trim()
                val serverIdentityPublicKey =
                    item.optString(KEY_SERVER_IDENTITY_PUBLIC_KEY)
                        .takeIf { it.isNotBlank() }
                        ?: item.optString("serverPublicKey")
                if (
                    id.isEmpty() ||
                        publicAddress.isEmpty() ||
                        serverIdentityPublicKey.trim().isEmpty()
                ) {
                    continue
                }

                add(
                        PairedServerRecord(
                                id = id,
                                publicAddress = publicAddress,
                                serverIdentityPublicKey = serverIdentityPublicKey.trim(),
                                supportedProtocols =
                                        parseProtocols(item.optJSONArray("supportedProtocols")),
                            peerShareEnabled = item.optBoolean("peerShareEnabled", false),
                            peerShareBindAddress =
                                item.optString("peerShareBindAddress", ""),
                            peerShareAdvertiseIp =
                                item.optString("peerShareAdvertiseIp", ""),
                            peerShareMaxConsumers = item.optInt("peerShareMaxConsumers", 4),
                            peerShareRelayBandwidthKbps =
                                item.optLong("peerShareRelayBandwidthKbps", 0),
                                pairedAt = item.optString("pairedAt", Instant.now().toString()),
                            lastResolvedAddress = item.optString("lastResolvedAddress", ""),
                            diagnosticsUploadEnabled =
                                item.optBoolean("diagnosticsUploadEnabled", false),
                            diagnosticsUploadPeriodSecs =
                                item.optLong("diagnosticsUploadPeriodSecs", 900),
                        ),
                )
            }
        }
    }

    private fun parseLegacySingleRecord(
            prefs: android.content.SharedPreferences
    ): PairedServerRecord? {
        val id = prefs.getString(LEGACY_KEY_DEVICE_ID, "")?.trim().orEmpty()
        val publicAddress = prefs.getString(LEGACY_KEY_PUBLIC_ADDRESS, "")?.trim().orEmpty()
        val serverIdentityPublicKey =
            prefs.getString(KEY_SERVER_IDENTITY_PUBLIC_KEY, null)?.trim().orEmpty().ifEmpty {
                prefs.getString(LEGACY_KEY_SERVER_PUBLIC_KEY, "")?.trim().orEmpty()
            }
        if (id.isEmpty() || publicAddress.isEmpty() || serverIdentityPublicKey.isEmpty()) {
            return null
        }

        return PairedServerRecord(
                id = id,
                publicAddress = publicAddress,
                serverIdentityPublicKey = serverIdentityPublicKey,
                supportedProtocols = emptyList(),
                peerShareEnabled = false,
                peerShareBindAddress = "",
                peerShareAdvertiseIp = "",
                peerShareMaxConsumers = 4,
                peerShareRelayBandwidthKbps = 0,
                pairedAt = prefs.getString(LEGACY_KEY_PAIRED_AT, Instant.now().toString())
                                ?: Instant.now().toString(),
        )
    }
}
