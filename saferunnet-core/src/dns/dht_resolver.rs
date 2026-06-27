use crate::dns::resolver::{is_loki_name, DhtClient, DnsError, LokiResolver};
use saferunnet_crypto::PublicKey;
use std::collections::HashMap;
use std::sync::Mutex;

pub struct DhtLokiResolver<C: DhtClient> {
    client: C,
    cache: Mutex<HashMap<String, Vec<PublicKey>>>,
}

impl<C: DhtClient> DhtLokiResolver<C> {
    pub fn new(client: C) -> Self {
        Self {
            client,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

impl<C: DhtClient> LokiResolver for DhtLokiResolver<C> {
    fn resolve(&self, name: &str) -> Result<Vec<PublicKey>, DnsError> {
        if !is_loki_name(name) {
            return Err(DnsError::NotLokiName(name.to_string()));
        }

        {
            let cache = self.cache.lock().unwrap();
            if let Some(result) = cache.get(name) {
                if !result.is_empty() {
                    return Ok(result.clone());
                }
            }
        }

        let target = derive_key_from_loki_name(name);
        let results = self.client.lookup_intro_set(&target);
        let keys: Vec<PublicKey> = results.iter().map(|r| r.public_key.clone()).collect();

        if keys.is_empty() {
            return Err(DnsError::NotFound(name.to_string()));
        }

        let mut cache = self.cache.lock().unwrap();
        cache.insert(name.to_string(), keys.clone());

        Ok(keys)
    }
}

fn derive_key_from_loki_name(name: &str) -> PublicKey {
    use std::hash::{Hash, Hasher};
    let host = name.strip_suffix(".loki").unwrap_or(name);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    host.hash(&mut hasher);
    let hash = hasher.finish();
    let mut key_bytes = [0u8; 32];
    key_bytes[0..8].copy_from_slice(&hash.to_le_bytes());
    for (i, byte) in key_bytes.iter_mut().enumerate().skip(8) {
        *byte = (hash >> ((i % 8) * 8)) as u8;
    }
    PublicKey::from_bytes(saferunnet_crypto::KeyAlgorithm::Ed25519, key_bytes)
}

#[cfg(test)]
use crate::dns::resolver::DhtIntroResult;
#[cfg(test)]
mod tests {
    use super::*;
    use saferunnet_crypto::{Ed25519KeyGenerator, KeyAlgorithm, KeyGenerator};

    struct StubDhtClient {
        results: Vec<DhtIntroResult>,
    }

    impl DhtClient for StubDhtClient {
        fn lookup_intro_set(&self, _target: &PublicKey) -> Vec<DhtIntroResult> {
            self.results.clone()
        }
    }

    #[test]
    fn dht_resolver_rejects_non_loki_name() {
        let client = StubDhtClient { results: vec![] };
        let resolver = DhtLokiResolver::new(client);
        let result = resolver.resolve("google.com");
        assert!(matches!(result, Err(DnsError::NotLokiName(_))));
    }

    #[test]
    fn dht_resolver_returns_keys() {
        let keygen = Ed25519KeyGenerator::new();
        let key_pair = keygen
            .generate(KeyAlgorithm::Ed25519)
            .expect("test key generation should succeed");
        let pk = key_pair.public_key;

        let client = StubDhtClient {
            results: vec![DhtIntroResult {
                public_key: pk.clone(),
                addresses: vec!["10.0.0.1:1090".into()],
            }],
        };
        let resolver = DhtLokiResolver::new(client);
        let result = resolver.resolve("myservice.loki").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_bytes(), pk.to_bytes());
    }

    #[test]
    fn dht_resolver_not_found() {
        let client = StubDhtClient { results: vec![] };
        let resolver = DhtLokiResolver::new(client);
        let result = resolver.resolve("unknown.loki");
        assert!(matches!(result, Err(DnsError::NotFound(_))));
    }

    #[test]
    fn dht_resolver_caches_results() {
        let keygen = Ed25519KeyGenerator::new();
        let key_pair = keygen
            .generate(KeyAlgorithm::Ed25519)
            .expect("test key generation should succeed");
        let pk = key_pair.public_key;

        // Create a client that panics if called more than once
        struct SingleCallClient {
            pk: PublicKey,
            called: Mutex<bool>,
        }
        impl DhtClient for SingleCallClient {
            fn lookup_intro_set(&self, _target: &PublicKey) -> Vec<DhtIntroResult> {
                let mut called = self.called.lock().unwrap();
                assert!(
                    !*called,
                    "DHT client should only be called once due to cache"
                );
                *called = true;
                vec![DhtIntroResult {
                    public_key: self.pk.clone(),
                    addresses: vec![],
                }]
            }
        }

        let client = SingleCallClient {
            pk: pk.clone(),
            called: Mutex::new(false),
        };
        let resolver = DhtLokiResolver::new(client);
        let r1 = resolver.resolve("cached.loki").unwrap();
        let r2 = resolver.resolve("cached.loki").unwrap();
        assert_eq!(r1, r2);
    }
}
