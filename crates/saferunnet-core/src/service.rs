use std::any::{Any, TypeId};
use std::collections::HashMap;

#[derive(Default)]
pub struct ServiceRegistry {
    services: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert<T>(&mut self, service: T) -> Option<T>
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
}
