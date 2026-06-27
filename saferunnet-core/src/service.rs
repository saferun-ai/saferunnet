use std::any::{Any, TypeId};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceKey {
    type_id: TypeId,
    name: &'static str,
}

impl ServiceKey {
    pub const fn of<T: 'static>(name: &'static str) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            name,
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }
}

#[derive(Default)]
pub struct ServiceRegistry {
    services: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
    keys: HashMap<&'static str, TypeId>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert<T>(&mut self, service: T) -> Option<T>
    where
        T: Send + Sync + 'static,
    {
        self.keys
            .insert(std::any::type_name::<T>(), TypeId::of::<T>());
        self.insert_inner(service)
    }

    pub fn insert_named<T>(&mut self, key: &'static str, service: T) -> Option<T>
    where
        T: Send + Sync + 'static,
    {
        self.keys.insert(key, TypeId::of::<T>());
        self.insert_inner(service)
    }

    fn insert_inner<T>(&mut self, service: T) -> Option<T>
    where
        T: Send + Sync + 'static,
    {
        self.services
            .insert(TypeId::of::<T>(), Box::new(service))
            .and_then(|previous| previous.downcast::<T>().ok().map(|boxed| *boxed))
    }

    pub fn get<T>(&self) -> Option<&T>
    where
        T: Send + Sync + 'static,
    {
        self.services
            .get(&TypeId::of::<T>())
            .and_then(|service| service.downcast_ref::<T>())
    }

    pub fn contains_key(&self, key: &'static str) -> bool {
        self.keys.contains_key(key)
    }

    pub fn register_with_key(
        &mut self,
        key: ServiceKey,
        value: Box<dyn Any + Send + Sync>,
    ) -> Option<Box<dyn Any + Send + Sync>> {
        self.keys.insert(key.name, key.type_id);
        self.services.insert(key.type_id, value)
    }

    pub fn get_by_key<T: 'static>(&self, _key: &ServiceKey) -> Option<&T> {
        self.services
            .get(&TypeId::of::<T>())
            .and_then(|service| service.downcast_ref::<T>())
    }

    pub fn get_named<T: Send + Sync + 'static>(&self, key: &str) -> Option<&T> {
        self.keys.get(key).and_then(|type_id| {
            self.services
                .get(type_id)
                .and_then(|service| service.downcast_ref::<T>())
        })
    }

    pub fn clear_registrations(&mut self) {
        self.services.clear();
        self.keys.clear();
    }

    pub fn contains_key_typed(&self, key: &ServiceKey) -> bool {
        self.keys.contains_key(key.name)
    }
}
