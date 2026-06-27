import re

path = r"D:\Projects\RustProjects\ReburnSaferunNet\crates\saferunnet-service\src\lib.rs"
with open(path, "r") as f:
    content = f.read()

print("Original length:", len(content))

# 1. mod declarations: insert before session_types
content = content.replace(
    "mod session_types;",
    "mod dht_intro;\nmod path_build;\nmod session_types;\nmod transit_hop;"
)

# 2. pub use: insert before session_types use
content = content.replace(
    "pub use session_types::{SessionHopId, SessionTag};",
    "pub use dht_intro::{\n    AddressFamily, AuthenticatedDhtIntroMessage, DhtIntroEntry, DhtIntroError, DhtIntroMessage,\n};\npub use path_build::{\n    AuthenticatedPathBuildMessage, AuthenticatedPathBuildResponse, PathBuildError,\n    PathBuildMessage, PathBuildResponse, PathHop,\n};\npub use session_types::{SessionHopId, SessionTag};\npub use transit_hop::{\n    AuthenticatedTransitHopMessage, TransitHopError, TransitHopMessage,\n};"
)

# 3. Enum - replace closing brace
content = content.replace(
    "    LinkSessionClose,\n}",
    "    LinkSessionClose,\n    LinkPathBuild,\n    LinkPathBuildResponse,\n    DhtIntro,\n    LinkTransitHop,\n}"
)

# Verify enum change
if "LinkTransitHop" in content:
    print("Enum: LinkTransitHop FOUND")
else:
    print("Enum: LinkTransitHop NOT FOUND")
    idx = content.find("LinkSessionClose,")
    if idx >= 0:
        print("Context:", repr(content[idx:idx+100]))

# 4. encode_kind
content = content.replace(
    "        ServiceMessageKind::LinkSessionClose => 7,\n    }\n}",
    "        ServiceMessageKind::LinkSessionClose => 7,\n        ServiceMessageKind::DhtIntro => 8,\n        ServiceMessageKind::LinkPathBuild => 9,\n        ServiceMessageKind::LinkPathBuildResponse => 10,\n        ServiceMessageKind::LinkTransitHop => 11,\n    }\n}"
)

# 5. decode_kind
content = content.replace(
    "        7 => Ok(ServiceMessageKind::LinkSessionClose),\n        _ => Err(ServiceMessageError::FrameMalformed(",
    "        7 => Ok(ServiceMessageKind::LinkSessionClose),\n        8 => Ok(ServiceMessageKind::DhtIntro),\n        9 => Ok(ServiceMessageKind::LinkPathBuild),\n        10 => Ok(ServiceMessageKind::LinkPathBuildResponse),\n        11 => Ok(ServiceMessageKind::LinkTransitHop),\n        _ => Err(ServiceMessageError::FrameMalformed("
)

print("New length:", len(content))
print("Has LinkTransitHop:", "LinkTransitHop" in content)
print("Has DhtIntro:", "DhtIntro" in content)
print("Has LinkPathBuild:", "LinkPathBuild" in content)

with open(path, "w") as f:
    f.write(content)

print("Written successfully")
