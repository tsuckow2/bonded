package com.bonded.bonded_app

import java.math.BigInteger
import java.net.InetAddress

/** All 128 bits set: the top of the IPv6 space. */
private val IPV6_ALL_ONES: BigInteger = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)

/**
 * An IPv6 CIDR block. [address] is held as an unsigned 128-bit value in a
 * BigInteger so the full space stays positive. Pure Kotlin with no Android
 * dependency (java.net is JDK), so it is unit-testable on the JVM.
 *
 * Mirrors Ipv4Cidr for the 128-bit space: local-traffic mode needs the
 * same complement computation for IPv6, so an IPv6 route can capture
 * everything except the attached subnets. Captured IPv6 is fail-closed —
 * the server drops v6 packets today (no v6 forwarding) — so the complement
 * exists to keep LAN IPv6 working, not to keep internet IPv6 working.
 */
data class Ipv6Cidr(val address: BigInteger, val prefix: Int) {
    init {
        require(prefix in 0..128) { "prefix out of range: $prefix" }
        require(address.signum() >= 0 && address <= IPV6_ALL_ONES) {
            "address out of range: $address"
        }
    }

    /** Network address with host bits cleared. */
    val network: BigInteger
        get() = address and mask()

    /** First address in the block. */
    val first: BigInteger
        get() = network

    /** Last address in the block. */
    val last: BigInteger
        get() = network or IPV6_ALL_ONES.shiftRight(prefix)

    private fun mask(): BigInteger =
            if (prefix == 0) BigInteger.ZERO
            else IPV6_ALL_ONES.shiftLeft(128 - prefix).and(IPV6_ALL_ONES)

    fun contains(ip: BigInteger): Boolean = ip in first..last

    /**
     * Full uncompressed form (8 groups of 4 hex digits). Always parseable
     * by InetAddress, which is what the builder route strings need; no
     * :: compression logic to get wrong.
     */
    fun toAddressString(): String {
        val a = network
        return (0 until 8).joinToString(":") { group ->
            val value = a.shiftRight(112 - 16 * group).and(BigInteger.valueOf(0xFFFF))
            value.toString(16).padStart(4, '0')
        }
    }

    override fun toString(): String = "${toAddressString()}/$prefix"

    companion object {
        fun fromAddressString(address: String, prefix: Int): Ipv6Cidr {
            val inet = InetAddress.getByName(address)
            val bytes = inet.address
            require(bytes.size == 16) { "not an IPv6 address: $address" }
            return Ipv6Cidr(BigInteger(1, bytes), prefix)
        }

        fun fromBytes(bytes: ByteArray, prefix: Int): Ipv6Cidr {
            require(bytes.size == 16) { "not an IPv6 address: ${bytes.size} bytes" }
            return Ipv6Cidr(BigInteger(1, bytes), prefix)
        }
    }
}

/**
 * The minimal CIDR cover of all IPv6 space NOT in [excluded].
 *
 * Same algorithm as excludeSubnets, over 128-bit intervals: remaining
 * space starts whole, each excluded block punches its interval out
 * (overlaps and duplicates merge harmlessly), and each remaining
 * interval becomes its minimal CIDR list. Returns emptyList() when
 * everything is excluded.
 */
fun excludeIpv6Subnets(excluded: List<Ipv6Cidr>): List<Ipv6Cidr> {
    // Remaining address space as closed intervals, starting whole.
    val remaining = mutableListOf(BigInteger.ZERO to IPV6_ALL_ONES)
    for (block in excluded) {
        val start = block.first
        val end = block.last
        val next = mutableListOf<Pair<BigInteger, BigInteger>>()
        for ((lo, hi) in remaining) {
            if (end < lo || start > hi) {
                next.add(lo to hi) // no overlap
            } else {
                if (start > lo) next.add(lo to start.subtract(BigInteger.ONE))
                if (end < hi) next.add(end.add(BigInteger.ONE) to hi)
            }
        }
        remaining.clear()
        remaining.addAll(next)
        if (remaining.isEmpty()) break
    }
    // Each remaining interval becomes its minimal CIDR list.
    val result = mutableListOf<Ipv6Cidr>()
    for ((lo, hi) in remaining) {
        var cursor = lo
        while (cursor <= hi) {
            var size =
                    if (cursor == BigInteger.ZERO) BigInteger.ONE.shiftLeft(128)
                    else BigInteger.ONE.shiftLeft(cursor.getLowestSetBit())
            while (cursor.add(size).subtract(BigInteger.ONE) > hi) {
                size = size.shiftRight(1)
            }
            val prefix = 128 - size.getLowestSetBit()
            result.add(Ipv6Cidr(cursor, prefix))
            cursor = cursor.add(size)
        }
    }
    return result
}
