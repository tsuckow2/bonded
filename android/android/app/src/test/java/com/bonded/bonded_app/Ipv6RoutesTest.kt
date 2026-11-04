package com.bonded.bonded_app

import java.math.BigInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Ipv6RoutesTest {
    @Test
    fun exclude_nothing_returnsWholeSpace() {
        assertEquals(listOf(Ipv6Cidr(BigInteger.ZERO, 0)), excludeIpv6Subnets(emptyList()))
    }

    @Test
    fun exclude_everything_returnsEmpty() {
        assertEquals(
                emptyList<Ipv6Cidr>(),
                excludeIpv6Subnets(listOf(Ipv6Cidr(BigInteger.ZERO, 0))),
        )
    }

    @Test
    fun exclude_single64_coversEverythingElse() {
        val excluded = Ipv6Cidr.fromAddressString("fd00:10:8::", 64)
        val routes = excludeIpv6Subnets(listOf(excluded))
        assertFalse(routes.isEmpty())
        // Nothing in the complement may touch the excluded block.
        assertTrue(routes.none { it.first <= excluded.last && excluded.first <= it.last })
        // Spot checks: inside the exclusion is out, neighbours and the
        // internet are in.
        assertFalse(covers(routes, "fd00:10:8::1"))
        assertFalse(covers(routes, "fd00:10:8::"))
        assertFalse(covers(routes, "fd00:10:8:0:ffff:ffff:ffff:ffff"))
        assertTrue(covers(routes, "fd00:10:7:ffff:ffff:ffff:ffff:ffff"))
        assertTrue(covers(routes, "fd00:10:9::1"))
        assertTrue(covers(routes, "2001:db8::1"))
        assertTrue(covers(routes, "::"))
        assertTrue(covers(routes, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
        // Union of complement + exclusion is the whole space, with no gaps.
        val covered =
                routes.fold(BigInteger.ZERO) { acc, r ->
                    acc.add(r.last.subtract(r.first)).add(BigInteger.ONE)
                }
        assertEquals(BigInteger.ONE.shiftLeft(128), covered.add(BigInteger.ONE.shiftLeft(64)))
    }

    @Test
    fun exclude_hostRoute_punchesOneAddress() {
        val routes = excludeIpv6Subnets(listOf(Ipv6Cidr.fromAddressString("fd00:10:8::2", 128)))
        assertFalse(covers(routes, "fd00:10:8::2"))
        assertTrue(covers(routes, "fd00:10:8::1"))
        assertTrue(covers(routes, "fd00:10:8::3"))
    }

    @Test
    fun exclude_overlappingBlocks_mergesThem() {
        // The /64 must share the /48's first 48 bits to be contained:
        // fd00:10:0:8::, not fd00:10:8:: (whose third group differs).
        val by48 = excludeIpv6Subnets(listOf(Ipv6Cidr.fromAddressString("fd00:10::", 48)))
        val by48plus64 =
                excludeIpv6Subnets(
                        listOf(
                                Ipv6Cidr.fromAddressString("fd00:10::", 48),
                                Ipv6Cidr.fromAddressString("fd00:10:0:8::", 64),
                        )
                )
        assertEquals(by48, by48plus64)
        assertFalse(covers(by48plus64, "fd00:10:0:8::5"))
        assertFalse(covers(by48plus64, "fd00:10:0:ffff::1"))
        assertTrue(covers(by48plus64, "fd00:10:1::1"))
        assertTrue(covers(by48plus64, "fd00:11::1"))
    }

    @Test
    fun exclude_hostBitsAreCleared() {
        // fd00:10:8::ab/64 still means the whole /64.
        val routes = excludeIpv6Subnets(listOf(Ipv6Cidr.fromAddressString("fd00:10:8::ab", 64)))
        assertFalse(covers(routes, "fd00:10:8::5"))
        assertTrue(covers(routes, "fd00:10:9::1"))
    }

    @Test
    fun cidr_formatting_roundTrips() {
        val cidr = Ipv6Cidr.fromAddressString("fd00:10:8::", 64)
        assertEquals("fd00:0010:0008:0000:0000:0000:0000:0000/64", cidr.toString())
        assertEquals("fd00:0010:0008:0000:0000:0000:0000:0000", cidr.toAddressString())
        // fd00:0010:0008:: as bytes: fd 00 00 10 00 08, rest zero.
        val bytes = ByteArray(16)
        bytes[0] = 0xfd.toByte()
        bytes[3] = 0x10.toByte()
        bytes[5] = 0x08.toByte()
        assertEquals(Ipv6Cidr.fromBytes(bytes, 64), cidr)
    }

    private fun covers(routes: List<Ipv6Cidr>, address: String): Boolean {
        val ip = Ipv6Cidr.fromAddressString(address, 128).address
        return routes.any { it.contains(ip) }
    }
}
