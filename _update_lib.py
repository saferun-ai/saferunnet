import re

path = r"D:\Projects\RustProjects\ReburnSaferunNet\crates\saferunnet-service\src\lib.rs"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Add mod declarations after mod session_types;
content = content.replace(
    "mod session_types;",
    "mod dht_intro;\nmod path_build;\nmod session_types;\nmod transit_hop;"
)

# 2. Add pub use blocks after pub use session_types
content = content.replace(
    "pub use session_types::{SessionHopId, SessionTag};",
    """pub use dht_intro::{
    AddressFamily, AuthenticatedDhtIntroMessage, DhtIntroEntry, DhtIntroError, DhtIntroMessage,
};
pub use path_build::{
    AuthenticatedPathBuildMessage, AuthenticatedPathBuildResponse, PathBuildError,
    PathBuildMessage, PathBuildResponse, PathHop,
};
pub use session_types::{SessionHopId, SessionTag};
pub use transit_hop::{
    AuthenticatedTransitHopMessage, TransitHopError, TransitHopMessage,
};"""
)

# 3. Add variants to enum
content = content.replace(
    "    LinkSessionClose,\n}",
    "    LinkSessionClose,\n    LinkPathBuild,\n    LinkPathBuildResponse,\n    DhtIntro,\n    LinkTransitHop,\n}"
)

# 4. Add to encode_kind
content = content.replace(
    "        ServiceMessageKind::LinkSessionClose => 7,\n    }",
    "        ServiceMessageKind::LinkSessionClose => 7,\n        ServiceMessageKind::DhtIntro => 8,\n        ServiceMessageKind::LinkPathBuild => 9,\n        ServiceMessageKind::LinkPathBuildResponse => 10,\n        ServiceMessageKind::LinkTransitHop => 11,\n    }"
)

# 5. Add to decode_kind
content = content.replace(
    "        7 => Ok(ServiceMessageKind::LinkSessionClose),\n        _ => Err(ServiceMessageError::FrameMalformed(",
    "        7 => Ok(ServiceMessageKind::LinkSessionClose),\n        8 => Ok(ServiceMessageKind::DhtIntro),\n        9 => Ok(ServiceMessageKind::LinkPathBuild),\n        10 => Ok(ServiceMessageKind::LinkPathBuildResponse),\n        11 => Ok(ServiceMessageKind::LinkTransitHop),\n        _ => Err(ServiceMessageError::FrameMalformed("
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("lib.rs updated successfully")
