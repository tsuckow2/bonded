package com.bonded.bonded_app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalRoutesTest {
    @Test
    fun exclude_nothing_returnsWholeSpace() {
        assertEquals(listOf(Ipv4Cidr(0L, 0)), excludeSubnets(emptyList()))
    }

    @Test
    fun exclude_everything_returnsEmpty() {
        assertEquals(emptyList<Ipv4Cidr>(), excludeSubnets(listOf(Ipv4Cidr(0L, 0))))
    }

    @Test
    fun exclude_single24_coversEverythingElse() {
        val excluded = Ipv4Cidr.fromAddressString("192.168.1.0", 24)
        val routes = excludeSubnets(listOf(excluded))
        assertFalse(routes.isEmpty())
        // Nothing in the complement may touch the excluded block.
        assertTrue(routes.none { it.first <= excluded.last && excluded.first <= it.last })
        // Spot checks: inside the exclusion is out, neighbours and the
        // internet are in.
        assertFalse(covers(routes, "192.168.1.5"))
        assertFalse(covers(routes, "192.168.1.0"))
        assertFalse(covers(routes, "192.168.1.255"))
        assertTrue(covers(routes, "192.168.0.9"))
        assertTrue(covers(routes, "192.168.2.1"))
        assertTrue(covers(routes, "8.8.8.8"))
        assertTrue(covers(routes, "0.0.0.0"))
        assertTrue(covers(routes, "255.255.255.255"))
        // Union of complement + exclusion is the whole space, with no gaps.
        assertEquals(0x100000000L, routes.sumOf { it.last - it.first + 1 } + 256L)
    }

    @Test
    fun exclude_hostRoute_punchesOneAddress() {
        val routes = excludeSubnets(listOf(Ipv4Cidr.fromAddressString("10.8.0.2", 32)))
        assertFalse(covers(routes, "10.8.0.2"))
        assertTrue(covers(routes, "10.8.0.1"))
        assertTrue(covers(routes, "10.8.0.3"))
    }

    @Test
    fun exclude_overlappingBlocks_mergesThem() {
        val by16 = excludeSubnets(listOf(Ipv4Cidr.fromAddressString("192.168.0.0", 16)))
        val by16plus24 =
                excludeSubnets(
                        listOf(
                                Ipv4Cidr.fromAddressString("192.168.0.0", 16),
                                Ipv4Cidr.fromAddressString("192.168.1.0", 24),
                        )
                )
        assertEquals(by16, by16plus24)
        assertFalse(covers(by16plus24, "192.168.1.5"))
        assertFalse(covers(by16plus24, "192.168.2.1"))
        assertTrue(covers(by16plus24, "192.169.0.1"))
    }

    @Test
    fun exclude_hostBitsAreCleared() {
        // 192.168.1.200/24 still means the whole /24.
        val routes = excludeSubnets(listOf(Ipv4Cidr.fromAddressString("192.168.1.200", 24)))
        assertFalse(covers(routes, "192.168.1.5"))
        assertTrue(covers(routes, "192.168.2.1"))
    }

    @Test
    fun exclude_multipleSubnets_allStayOut() {
        val routes =
                excludeSubnets(
                        listOf(
                                Ipv4Cidr.fromAddressString("10.0.0.0", 8),
                                Ipv4Cidr.fromAddressString("192.168.0.0", 16),
                                Ipv4Cidr.fromAddressString("172.16.0.0", 12),
                        )
                )
        assertFalse(covers(routes, "10.1.2.3"))
        assertFalse(covers(routes, "192.168.5.5"))
        assertFalse(covers(routes, "172.20.0.1"))
        assertTrue(covers(routes, "172.32.0.1"))
        assertTrue(covers(routes, "11.0.0.1"))
        assertTrue(covers(routes, "1.1.1.1"))
    }

    @Test
    fun cidr_formatting_roundTrips() {
        val cidr = Ipv4Cidr.fromAddressString("192.168.1.0", 24)
        assertEquals("192.168.1.0/24", cidr.toString())
        assertEquals("192.168.1.0", cidr.toAddressString())
        assertEquals(Ipv4Cidr.fromBytes(byteArrayOf(192.toByte(), 168.toByte(), 1, 0), 24), cidr)
    }

    private fun covers(routes: List<Ipv4Cidr>, address: String): Boolean {
        val ip = Ipv4Cidr.fromAddressString(address, 32).address
        return routes.any { it.contains(ip) }
    }
}
