package com.bonded.bonded_app

/**
 * An IPv4 CIDR block. [address] is held as an unsigned 32-bit value in a
 * Long so 128.0.0.0/1 and above stay positive. Pure Kotlin with no Android
 * dependency, so it is unit-testable on the JVM.
 */
data class Ipv4Cidr(val address: Long, val prefix: Int) {
    init {
        require(prefix in 0..32) { "prefix out of range: $prefix" }
        require(address in 0..0xFFFFFFFFL) { "address out of range: $address" }
    }

    /** Network address with host bits cleared. */
    val network: Long
        get() = address and mask()

    /** First address in the block. */
    val first: Long
        get() = network

    /** Last address in the block. */
    val last: Long
        get() = network or (0xFFFFFFFFL ushr prefix)

    private fun mask(): Long =
            if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL

    fun contains(ip: Long): Boolean = ip in first..last

    fun toAddressString(): String {
        val a = network
        return "${(a ushr 24) and 0xFF}.${(a ushr 16) and 0xFF}.${(a ushr 8) and 0xFF}.${a and 0xFF}"
    }

    override fun toString(): String = "${toAddressString()}/$prefix"

    companion object {
        fun fromAddressString(address: String, prefix: Int): Ipv4Cidr {
            val parts = address.split(".")
            require(parts.size == 4) { "not an IPv4 address: $address" }
            var value = 0L
            for (part in parts) {
                val octet = part.toInt()
                require(octet in 0..255) { "octet out of range: $part" }
                value = (value shl 8) or octet.toLong()
            }
            return Ipv4Cidr(value, prefix)
        }

        fun fromBytes(bytes: ByteArray, prefix: Int): Ipv4Cidr {
            require(bytes.size == 4) { "not an IPv4 address: ${bytes.size} bytes" }
            var value = 0L
            for (b in bytes) value = (value shl 8) or (b.toLong() and 0xFF)
            return Ipv4Cidr(value, prefix)
        }
    }
}

/**
 * The minimal CIDR cover of all IPv4 space NOT in [excluded].
 *
 * VpnService.Builder has no route-exclusion API, so local-traffic mode
 * replaces the single 0.0.0.0/0 route with this complement: the physical
 * interfaces keep their own connected routes, which win by longest-prefix
 * match, so traffic for an excluded subnet never enters the TUN.
 *
 * Excluded blocks are normalized to their network address and merged, so
 * overlaps and duplicates cannot punch holes or double-cover. Returns
 * emptyList() when everything is excluded.
 */
fun excludeSubnets(excluded: List<Ipv4Cidr>): List<Ipv4Cidr> {
    // Remaining address space as closed intervals, starting whole.
    val remaining = mutableListOf(0L to 0xFFFFFFFFL)
    for (block in excluded) {
        val start = block.first
        val end = block.last
        val next = mutableListOf<Pair<Long, Long>>()
        for ((lo, hi) in remaining) {
            if (end < lo || start > hi) {
                next.add(lo to hi) // no overlap
            } else {
                if (start > lo) next.add(lo to start - 1)
                if (end < hi) next.add(end + 1 to hi)
            }
        }
        remaining.clear()
        remaining.addAll(next)
        if (remaining.isEmpty()) break
    }
    // Each remaining interval becomes its minimal CIDR list.
    val result = mutableListOf<Ipv4Cidr>()
    for ((lo, hi) in remaining) {
        var cursor = lo
        while (cursor <= hi) {
            var size = if (cursor == 0L) (1L shl 32) else java.lang.Long.lowestOneBit(cursor)
            while (cursor + size - 1 > hi) size = size shr 1
            val prefix = 32 - java.lang.Long.numberOfTrailingZeros(size)
            result.add(Ipv4Cidr(cursor, prefix))
            cursor += size
        }
    }
    return result
}
