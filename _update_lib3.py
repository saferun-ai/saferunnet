"""Update lib.rs with DhtIntro, PathBuild, and TransitHop families."""
path = r"D:\Projects\RustProjects\ReburnSaferunNet\crates\saferunnet-service\src\lib.rs"
with open(path, "r") as f:
    text = f.read()

# replacements is a list of (old, new) pairs
replacements = [
    # 1. mod declarations
    (
        "mod session_types;",
        "mod dht_intro;\nmod path_build;\nmod session_types;\nmod transit_hop;"
    ),
    # 2. pub use blocks (ordered: dht_intro, path_build before session_types)
    (
        "pub use session_types::{SessionHopId, SessionTag};",
        "pub use dht_intro::{\n    AddressFamily, AuthenticatedDhtIntroMessage, DhtIntroEntry, DhtIntroError, DhtIntroMessage,\n};\npub use path_build::{\n    AuthenticatedPathBuildMessage, AuthenticatedPathBuildResponse, PathBuildError,\n    PathBuildMessage, PathBuildResponse, PathHop,\n};\npub use session_types::{SessionHopId, SessionTag};\npub use transit_hop::{\n    AuthenticatedTransitHopMessage, TransitHopError, TransitHopMessage,\n};"
    ),
    # 3. Enum variants - replace the last variant + closing brace
    (
        "    LinkSessionClose,\n}\n\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct AuthenticatedServiceMessage",
        "    LinkSessionClose,\n    LinkPathBuild,\n    LinkPathBuildResponse,\n    DhtIntro,\n    LinkTransitHop,\n}\n\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct AuthenticatedServiceMessage"
    ),
    # 4. encode_kind - replace whole function
    (
        "        ServiceMessageKind::LinkSessionClose => 7,\n    }\n}\n\nfn decode_kind",
        "        ServiceMessageKind::LinkSessionClose => 7,\n        ServiceMessageKind::DhtIntro => 8,\n        ServiceMessageKind::LinkPathBuild => 9,\n        ServiceMessageKind::LinkPathBuildResponse => 10,\n        ServiceMessageKind::LinkTransitHop => 11,\n    }\n}\n\nfn decode_kind"
    ),
    # 5. decode_kind - replace whole match
    (
        "        7 => Ok(ServiceMessageKind::LinkSessionClose),\n        _ => Err(ServiceMessageError::FrameMalformed(",
        "        7 => Ok(ServiceMessageKind::LinkSessionClose),\n        8 => Ok(ServiceMessageKind::DhtIntro),\n        9 => Ok(ServiceMessageKind::LinkPathBuild),\n        10 => Ok(ServiceMessageKind::LinkPathBuildResponse),\n        11 => Ok(ServiceMessageKind::LinkTransitHop),\n        _ => Err(ServiceMessageError::FrameMalformed("
    ),
]

for old, new in replacements:
    if old not in text:
        print(f"WARNING: pattern not found: {old[:60]}...")
    else:
        text = text.replace(old, new)
        print(f"OK: replaced pattern starting with: {old[:40]}...")

with open(path, "w") as f:
    f.write(text)
print("\nDone. Verifying...")

# Verify
with open(path, "r") as f:
    verify = f.read()
for token in ["LinkTransitHop", "LinkPathBuild", "LinkPathBuildResponse", "DhtIntro", "transit_hop"]:
    count = verify.count(token)
    print(f"  {token}: found {count} time(s)")
