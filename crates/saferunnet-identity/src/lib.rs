use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

use saferunnet_crypto::{
    KeyAlgorithm, KeyGenerationError, KeyGenerator, KeyMaterialError, KeyPair, PublicKey, SecretKey,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    pub nickname: String,
    pub algorithm: KeyAlgorithm,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySpec {
    pub nickname: String,
    pub algorithm: KeyAlgorithm,
}

pub struct FileIdentityRepository {
    path: PathBuf,
}

impl FileIdentityRepository {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn save(&self, identity: &NodeIdentity) -> Result<(), IdentityRepositoryError> {
        let contents = format!(
            "nickname={}\nalgorithm={}\nsecret_key={}\npublic_key={}\n",
            identity.nickname,
            identity.algorithm.as_str(),
            identity.secret_key.to_hex(),
            identity.public_key.to_hex()
        );
        std::fs::write(&self.path, contents).map_err(|source| IdentityRepositoryError::Write {
            path: self.path.display().to_string(),
            source,
        })
    }

    pub fn load(&self) -> Result<NodeIdentity, IdentityRepositoryError> {
        let contents = std::fs::read_to_string(&self.path).map_err(|source| {
            IdentityRepositoryError::Read {
                path: self.path.display().to_string(),
                source,
            }
        })?;
        parse_identity(&contents)
    }

    pub fn load_or_create(
        &self,
        spec: &IdentitySpec,
        generator: &dyn KeyGenerator,
    ) -> Result<NodeIdentity, IdentityRepositoryError> {
        match self.load() {
            Ok(identity) => Ok(identity),
            Err(IdentityRepositoryError::Read { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                let generated = generator.generate(spec.algorithm)?;
                let identity = build_identity(spec, generated);
                self.save(&identity)?;
                Ok(identity)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug, Error)]
pub enum IdentityRepositoryError {
    #[error("failed to read identity file `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write identity file `{path}`: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("missing required identity field `{0}`")]
    MissingField(&'static str),
    #[error(transparent)]
    KeyMaterial(#[from] KeyMaterialError),
    #[error(transparent)]
    KeyGeneration(#[from] KeyGenerationError),
    #[error("invalid algorithm: {0}")]
    InvalidAlgorithm(String),
}

fn build_identity(spec: &IdentitySpec, key_pair: KeyPair) -> NodeIdentity {
    NodeIdentity {
        nickname: spec.nickname.clone(),
        algorithm: spec.algorithm,
        secret_key: key_pair.secret_key,
        public_key: key_pair.public_key,
    }
}

fn parse_identity(contents: &str) -> Result<NodeIdentity, IdentityRepositoryError> {
    let mut fields = BTreeMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            fields.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    let nickname = fields
        .get("nickname")
        .cloned()
        .ok_or(IdentityRepositoryError::MissingField("nickname"))?;
    let algorithm_text = fields
        .get("algorithm")
        .cloned()
        .ok_or(IdentityRepositoryError::MissingField("algorithm"))?;
    let algorithm = KeyAlgorithm::from_str(&algorithm_text)
        .map_err(|_| IdentityRepositoryError::InvalidAlgorithm(algorithm_text.clone()))?;
    let secret_key = SecretKey::from_hex(
        algorithm,
        fields
            .get("secret_key")
            .ok_or(IdentityRepositoryError::MissingField("secret_key"))?,
    )?;
    let public_key = PublicKey::from_hex(
        algorithm,
        fields
            .get("public_key")
            .ok_or(IdentityRepositoryError::MissingField("public_key"))?,
    )?;

    Ok(NodeIdentity {
        nickname,
        algorithm,
        secret_key,
        public_key,
    })
}
