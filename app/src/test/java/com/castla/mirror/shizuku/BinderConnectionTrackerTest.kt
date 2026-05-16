package com.castla.mirror.shizuku

import com.castla.mirror.shizuku.BinderConnectionTracker.Transition
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BinderConnectionTrackerTest {

    @Test
    fun firstConnect_returnsFirstConnect() {
        val tracker = BinderConnectionTracker()
        assertEquals(Transition.FirstConnect, tracker.onConnected())
        assertTrue(tracker.isConnected())
    }

    @Test
    fun secondConnect_withoutDisconnect_returnsIdempotent() {
        // Reproduces the cascade source: VirtualDisplayManager used to treat
        // every onServiceConnected after the first as a death/reconnect, which
        // spawned a new VD per spurious callback. Tracker must classify these
        // as no-ops so the reconnect handler does not run.
        val tracker = BinderConnectionTracker()
        tracker.onConnected()
        assertEquals(Transition.Idempotent, tracker.onConnected())
        assertEquals(Transition.Idempotent, tracker.onConnected())
    }

    @Test
    fun connectAfterDisconnect_returnsReconnect() {
        val tracker = BinderConnectionTracker()
        tracker.onConnected()
        tracker.onDisconnected()
        assertEquals(Transition.Reconnect, tracker.onConnected())
    }

    @Test
    fun disconnectFromNew_returnsIdempotent() {
        val tracker = BinderConnectionTracker()
        assertEquals(Transition.Idempotent, tracker.onDisconnected())
    }

    @Test
    fun disconnectFromNew_keepsStateAtNew_soNextConnectIsFirstConnect() {
        // Reproduces the bug where MutableStateFlow's initial `false` emission
        // to a fresh collector advanced the tracker to Disconnected, causing
        // the next real connect to be classified as Reconnect.
        val tracker = BinderConnectionTracker()
        tracker.onDisconnected()
        assertEquals(Transition.FirstConnect, tracker.onConnected())
    }

    @Test
    fun multipleDisconnects_withoutInterveningConnect_emitDisconnectOnceThenIdempotent() {
        val tracker = BinderConnectionTracker()
        tracker.onConnected()
        assertEquals(Transition.Disconnect, tracker.onDisconnected())
        assertEquals(Transition.Idempotent, tracker.onDisconnected())
    }

    @Test
    fun reset_returnsToNew_soNextConnectIsFirstConnect() {
        val tracker = BinderConnectionTracker()
        tracker.onConnected()
        tracker.onDisconnected()
        tracker.reset()
        assertFalse(tracker.isConnected())
        assertEquals(Transition.FirstConnect, tracker.onConnected())
    }

    @Test
    fun fullSequence_connectDisconnectConnectConnect_classifiesEachStep() {
        val tracker = BinderConnectionTracker()
        assertEquals(Transition.FirstConnect, tracker.onConnected())
        assertEquals(Transition.Disconnect, tracker.onDisconnected())
        assertEquals(Transition.Reconnect, tracker.onConnected())
        assertEquals(Transition.Idempotent, tracker.onConnected())
    }

    @Test
    fun isConnected_reflectsCurrentState() {
        val tracker = BinderConnectionTracker()
        assertFalse(tracker.isConnected())
        tracker.onConnected()
        assertTrue(tracker.isConnected())
        tracker.onDisconnected()
        assertFalse(tracker.isConnected())
    }
}
