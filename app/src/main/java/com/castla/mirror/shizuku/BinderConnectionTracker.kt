package com.castla.mirror.shizuku

/**
 * State machine that distinguishes a fresh connect from a reconnect after a real
 * disconnect event. Pure logic; no Android dependency so it can be unit-tested.
 *
 * Why this exists: prior to this fix, [VirtualDisplayManager] treated every
 * [android.content.ServiceConnection.onServiceConnected] callback after the
 * first as `service died, recreate VD`. Concurrent Shizuku binds (one from
 * `VirtualDisplayManager`, one from [ShizukuSetup]) produced multiple
 * onServiceConnected callbacks back-to-back, and the recreate path spawned a
 * new VirtualDisplay per spurious callback — yielding 6+ orphan VDs per
 * session and breaking app launching from the web launcher.
 *
 * The tracker classifies callbacks against a real [State.Disconnected] event
 * so duplicate connects are inert.
 */
class BinderConnectionTracker {
    enum class Transition { FirstConnect, Reconnect, Idempotent, Disconnect }
    private enum class State { New, Connected, Disconnected }
    private var state = State.New

    fun onConnected(): Transition = when (state) {
        State.New -> {
            state = State.Connected
            Transition.FirstConnect
        }
        State.Disconnected -> {
            state = State.Connected
            Transition.Reconnect
        }
        State.Connected -> Transition.Idempotent
    }

    fun onDisconnected(): Transition = when (state) {
        State.Connected -> {
            state = State.Disconnected
            Transition.Disconnect
        }
        // Disconnect from New (e.g. StateFlow's initial `false` emission to a
        // fresh collector) must NOT advance to Disconnected, otherwise the next
        // real connect would be misclassified as Reconnect and trigger the VD
        // recreate path.
        State.New, State.Disconnected -> Transition.Idempotent
    }

    fun isConnected(): Boolean = state == State.Connected

    fun reset() {
        state = State.New
    }
}
