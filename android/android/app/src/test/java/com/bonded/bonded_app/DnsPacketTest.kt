package com.bonded.bonded_app

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** DNS wire-format query builder + response parser (plan 4.116).
 * The parser is the trust boundary for the refresh — a bad
 * response must never become a dial target — so the malformed
 * inputs are pinned here alongside the happy path. */
class DnsPacketTest {
    private val queryId = 0x1234

    /** A well-formed response for charter.codingwell.net with one
     * A record per entry in [answers]: each is (type, rdata). The
     * answer NAME is a compression pointer (0xC00C) at the question
     * name, as real resolvers emit. [rcode] sets the header RCODE;
     * [anCount] overrides the answer count when it must disagree
     * with the record list (truncation tests). */
    private fun dnsResponse(
            rcode: Int = 0,
            answers: List<Pair<Int, ByteArray>> = listOf(
                    1 to byteArrayOf(75, 164.toByte(), 64, 252.toByte())
            ),
            anCount: Int = answers.size,
            id: Int = queryId,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(id shr 8)
        out.write(id)
        out.write(0x81)
        out.write(0x80 or rcode) // QR + RD + RA, RCODE.
        out.write(0)
        out.write(1) // QDCOUNT = 1.
        out.write(anCount shr 8)
        out.write(anCount)
        out.write(0)
        out.write(0) // NSCOUNT = 0.
        out.write(0)
        out.write(0) // ARCOUNT = 0.
        // Question: charter.codingwell.net, QTYPE A, QCLASS IN.
        out.write(7)
        out.write("charter".toByteArray(Charsets.US_ASCII))
        out.write(10)
        out.write("codingwell".toByteArray(Charsets.US_ASCII))
        out.write(3)
        out.write("net".toByteArray(Charsets.US_ASCII))
        out.write(0)
        out.write(0)
        out.write(1)
        out.write(0)
        out.write(1)
        for ((type, rdata) in answers) {
            out.write(0xC0)
            out.write(0x0C) // NAME: pointer to the question name.
            out.write(type shr 8)
            out.write(type)
            out.write(0)
            out.write(1) // CLASS IN.
            out.write(0)
            out.write(0)
            out.write(0)
            out.write(60) // TTL 60.
            out.write(rdata.size shr 8)
            out.write(rdata.size)
            out.write(rdata)
        }
        return out.toByteArray()
    }

    @Test
    fun buildQuery_encodesHeaderQuestionAndType() {
        val query = buildDnsQuery("charter.codingwell.net", queryId)
        val expected = ByteArrayOutputStream()
        expected.write(0x12)
        expected.write(0x34) // ID.
        expected.write(0x01)
        expected.write(0x00) // Flags: recursion desired.
        expected.write(0)
        expected.write(1) // QDCOUNT = 1.
        expected.write(0)
        expected.write(0) // ANCOUNT = 0.
        expected.write(0)
        expected.write(0) // NSCOUNT = 0.
        expected.write(0)
        expected.write(0) // ARCOUNT = 0.
        expected.write(7)
        expected.write("charter".toByteArray(Charsets.US_ASCII))
        expected.write(10)
        expected.write("codingwell".toByteArray(Charsets.US_ASCII))
        expected.write(3)
        expected.write("net".toByteArray(Charsets.US_ASCII))
        expected.write(0)
        expected.write(0)
        expected.write(1) // QTYPE A.
        expected.write(0)
        expected.write(1) // QCLASS IN.
        assertArrayEquals(expected.toByteArray(), query)
    }

    @Test
    fun buildQuery_rejectsUnencodableHostnames() {
        assertNull(buildDnsQuery("", queryId))
        assertNull(buildDnsQuery("   ", queryId))
        assertNull(buildDnsQuery("charter..codingwell.net", queryId))
        assertNull(buildDnsQuery("a".repeat(64) + ".net", queryId))
        assertNull(buildDnsQuery("a.".repeat(127) + "net", queryId))
    }

    @Test
    fun parseResponse_returnsFirstARecord() {
        val address = parseDnsResponse(dnsResponse(), queryId)
        assertEquals("75.164.64.252", address?.hostAddress)
    }

    @Test
    fun parseResponse_skipsNonARecordsToFindTheA() {
        // A CNAME first (TYPE 5), then the A record: the parser
        // must walk past the CNAME instead of returning it or
        // giving up.
        val address =
                parseDnsResponse(
                        dnsResponse(
                                answers =
                                        listOf(
                                                5 to
                                                        byteArrayOf(
                                                                0xC0.toByte(),
                                                                0x0C,
                                                        ),
                                                1 to
                                                        byteArrayOf(
                                                                75,
                                                                164.toByte(),
                                                                64,
                                                                252.toByte(),
                                                        ),
                                        )
                        ),
                        queryId,
                )
        assertEquals("75.164.64.252", address?.hostAddress)
    }

    @Test
    fun parseResponse_rejectsMalformedInputs() {
        assertNull(parseDnsResponse(ByteArray(0), queryId))
        assertNull(parseDnsResponse(ByteArray(11), queryId))
        // Wrong transaction id: not our query's response.
        assertNull(parseDnsResponse(dnsResponse(id = 0x5678), queryId))
        // NXDOMAIN.
        assertNull(parseDnsResponse(dnsResponse(rcode = 3), queryId))
        // Server failure.
        assertNull(parseDnsResponse(dnsResponse(rcode = 2), queryId))
        // No answers.
        assertNull(parseDnsResponse(dnsResponse(answers = emptyList()), queryId))
        // Truncated mid-answer: the RDATA is cut short.
        val full = dnsResponse()
        assertNull(parseDnsResponse(full.copyOf(full.size - 2), queryId))
        // Truncated mid-question.
        assertNull(parseDnsResponse(full.copyOf(20), queryId))
        // A record with the wrong RDLENGTH is skipped, not returned.
        assertNull(
                parseDnsResponse(
                        dnsResponse(
                                answers =
                                        listOf(
                                                1 to
                                                        byteArrayOf(
                                                                75,
                                                                164.toByte(),
                                                                64,
                                                        )
                                        )
                        ),
                        queryId,
                )
        )
        // Answer count lies about a second record that is not
        // there: the parser walks the CNAME, then runs out of bytes.
        assertNull(
                parseDnsResponse(
                        dnsResponse(
                                answers =
                                        listOf(
                                                5 to
                                                        byteArrayOf(
                                                                0xC0.toByte(),
                                                                0x0C,
                                                        )
                                        ),
                                anCount = 2,
                        ),
                        queryId,
                )
        )
    }

    @Test
    fun isIpLiteralAddress_matchesResolveServerAddressEarly() {
        assertEquals(true, isIpLiteralAddress("75.164.73.150:443"))
        assertEquals(true, isIpLiteralAddress("[2001:db8::1]:443"))
        assertEquals(false, isIpLiteralAddress("charter.codingwell.net:443"))
        assertEquals(false, isIpLiteralAddress("charter.codingwell.net"))
        assertEquals(false, isIpLiteralAddress(""))
    }

    @Test
    fun isValidRefreshAddress_acceptsWellFormedDialTargets() {
        assertEquals(true, isValidRefreshAddress("75.164.64.252:443"))
        assertEquals(true, isValidRefreshAddress("[2001:db8::1]:443"))
        assertEquals(true, isValidRefreshAddress("75.164.64.252:1"))
        assertEquals(true, isValidRefreshAddress("75.164.64.252:65535"))
    }

    @Test
    fun isValidRefreshAddress_rejectsAnythingNotADialTarget() {
        // A hostname is not a dial target: the refresh is a
        // pre-resolved IP, and a hostname would re-introduce the
        // TUN DNS deadlock the freeze exists to avoid.
        assertEquals(false, isValidRefreshAddress("charter.codingwell.net:443"))
        assertEquals(false, isValidRefreshAddress("75.164.64.252"))
        assertEquals(false, isValidRefreshAddress("75.164.64.252:0"))
        assertEquals(false, isValidRefreshAddress("75.164.64.252:65536"))
        assertEquals(false, isValidRefreshAddress("75.164.64.252:443x"))
        assertEquals(false, isValidRefreshAddress(":443"))
        assertEquals(false, isValidRefreshAddress(""))
    }
}
