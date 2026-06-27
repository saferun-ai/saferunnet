use saferunnet_link::{FrameKind, LlarpFrame, MAX_FRAME_PAYLOAD};

/// Frame encode/decode with every variant.
#[test]
fn every_kind_encodes_and_decodes() {
    for (kind, name) in [
        (FrameKind::Control, "Control"),
        (FrameKind::RelayIntro, "RelayIntro"),
        (FrameKind::RelayData, "RelayData"),
        (FrameKind::SessionData, "SessionData"),
    ] {
        let frame = LlarpFrame::new(kind, 42, 1, format!("payload_{name}").into_bytes()).unwrap();
        let encoded = frame.encode();
        let decoded = LlarpFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.kind, kind, "kind mismatch for {name}");
        assert_eq!(decoded.path_id, 42, "path_id mismatch for {name}");
        assert_eq!(decoded.hop_index, 1, "hop_index mismatch for {name}");
        assert_eq!(decoded.payload, format!("payload_{name}").into_bytes());
    }
}

/// Empty payload is valid.
#[test]
fn empty_payload_is_valid() {
    let frame = LlarpFrame::new(FrameKind::Control, 0, 0, vec![]).unwrap();
    let decoded = LlarpFrame::decode(&frame.encode()).unwrap();
    assert!(decoded.payload.is_empty());
}

/// Maximum payload is valid.
#[test]
fn max_payload_is_valid() {
    let big = vec![0xAA; MAX_FRAME_PAYLOAD];
    let frame = LlarpFrame::new(FrameKind::RelayData, 1, 0, big.clone()).unwrap();
    let decoded = LlarpFrame::decode(&frame.encode()).unwrap();
    assert_eq!(decoded.payload.len(), MAX_FRAME_PAYLOAD);
}

/// Oversize payload is rejected on construction.
#[test]
fn oversize_payload_rejected() {
    let too_big = vec![0u8; MAX_FRAME_PAYLOAD + 1];
    assert!(LlarpFrame::new(FrameKind::Control, 0, 0, too_big).is_err());
}

/// Corrupted version byte is rejected.
#[test]
fn corrupted_version_rejected() {
    let frame = LlarpFrame::new(FrameKind::Control, 0, 0, b"x".to_vec()).unwrap();
    let mut encoded = frame.encode();
    encoded[0] = 99;
    let err = LlarpFrame::decode(&encoded).unwrap_err();
    assert!(err.to_string().contains("version"));
}

/// Corrupted kind byte is rejected.
#[test]
fn corrupted_kind_rejected() {
    let frame = LlarpFrame::new(FrameKind::Control, 0, 0, b"x".to_vec()).unwrap();
    let mut encoded = frame.encode();
    encoded[1] = 99;
    let err = LlarpFrame::decode(&encoded).unwrap_err();
    assert!(err.to_string().contains("kind"));
}

/// Truncated frame is rejected.
#[test]
fn truncated_frame_rejected() {
    let frame = LlarpFrame::new(FrameKind::RelayData, 7, 3, b"hello_world".to_vec()).unwrap();
    let encoded = frame.encode();
    // Chop off the last byte
    let truncated = &encoded[..encoded.len() - 1];
    assert!(LlarpFrame::decode(truncated).is_err());
}

/// Trailing junk after valid payload is rejected.
#[test]
fn trailing_junk_rejected() {
    let frame = LlarpFrame::new(FrameKind::Control, 0, 0, b"clean".to_vec()).unwrap();
    let mut encoded = frame.encode();
    encoded.extend_from_slice(&[0xFF, 0xEE]);
    assert!(LlarpFrame::decode(&encoded).is_err());
}
