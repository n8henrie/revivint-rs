//! Stand-in for `net` in the `diag` build.
//!
//! The bench protocol wants the RF path to be the only variable, and wants the
//! board receiving within a second of reset rather than after a Wi-Fi
//! association and an MQTT connect. Decoded frames are logged by the receive
//! loop either way, so nothing diagnostic is lost by dropping them here.

use revivint_core::DecodedFrame;

/// Discard a decoded frame. The receive loop has already logged it.
pub fn report(_frame: DecodedFrame) {}
