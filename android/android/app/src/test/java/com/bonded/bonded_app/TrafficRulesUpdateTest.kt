package com.bonded.bonded_app

import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Traffic-rules live push (4.51): the Dart UI pushes a new rule
 * table to the running Rust session through
 * `BondedVpnService.updateTrafficRules`. The Kotlin side is a
 * string passthrough — it never parses the JSON — so the only
 * behavior ownable in a local unit test is the no-session contract:
 * with no service instance running the push reports false and the
 * caller (Dart) treats it as "applies on next connect", never as an
 * error. The live path (instance present → JNI → engine swap) is
 * covered by the Rust-side engine tests plus the session tests.
 */
class TrafficRulesUpdateTest {
    @Test
    fun updateTrafficRulesReturnsFalseWithNoServiceInstance() {
        assertFalse(BondedVpnService.updateTrafficRules("{}"))
        assertFalse(
            BondedVpnService.updateTrafficRules(
                "{\"defaultMode\":\"redundant\",\"rules\":[]}",
            ),
        )
    }
}
