package com.bonded.bonded_app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// 4.78: poll revents classification for the outbound TUN loop —
// the loop exits only on a dead fd (POLLERR / POLLHUP / POLLNVAL),
// never on POLLIN or a spurious 0. The bits are the Linux poll(2)
// values, as in android.system.OsConstants; the mask is passed
// explicitly because the unit-test android.jar stubs those fields
// to 0, so the test verifies the classification logic, not the
// stub constants.
class TunPollTest {
    companion object {
        private const val POLLIN_BIT = 0x0001
        private const val POLLERR_BIT = 0x0008
        private const val POLLHUP_BIT = 0x0010
        private const val POLLNVAL_BIT = 0x0020
        private const val DEAD_MASK = POLLERR_BIT or POLLHUP_BIT or POLLNVAL_BIT
    }

    @Test
    fun pollInMeansFdAlive() {
        assertFalse(isTunFdDead(POLLIN_BIT.toShort(), DEAD_MASK))
    }

    @Test
    fun zeroReventsMeansFdAlive() {
        assertFalse(isTunFdDead(0, DEAD_MASK))
    }

    @Test
    fun pollErrMeansFdDead() {
        assertTrue(isTunFdDead(POLLERR_BIT.toShort(), DEAD_MASK))
    }

    @Test
    fun pollHupMeansFdDead() {
        assertTrue(isTunFdDead(POLLHUP_BIT.toShort(), DEAD_MASK))
    }

    @Test
    fun pollNvalMeansFdDead() {
        assertTrue(isTunFdDead(POLLNVAL_BIT.toShort(), DEAD_MASK))
    }

    @Test
    fun pollInPlusErrMeansFdDead() {
        assertTrue(isTunFdDead((POLLIN_BIT or POLLERR_BIT).toShort(), DEAD_MASK))
    }
}
