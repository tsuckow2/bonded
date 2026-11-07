package com.bonded.bonded_app

import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Per-transport grades live push (4.52): the Dart UI pushes the
 * grader's current grades to the running Rust session through
 * `BondedVpnService.updatePathGrades`. The Kotlin side is a string
 * passthrough — it never parses the JSON — so the only behavior
 * ownable in a local unit test is the no-session contract: with no
 * service instance running the push reports false and the caller
 * (Dart) treats it as "best transport ranks on RTT/loss", never as
 * an error. The live path (instance present → JNI → grade store) is
 * covered by the Rust-side FFI tests plus the session tests.
 */
class PathGradesUpdateTest {
    @Test
    fun updatePathGradesReturnsFalseWithNoServiceInstance() {
        assertFalse(BondedVpnService.updatePathGrades("[84,null,71]"))
        assertFalse(BondedVpnService.updatePathGrades("[]"))
    }
}
