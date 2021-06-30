use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

pub trait Bag: Any + std::fmt::Debug + Send + Sync {}

/// Pipeline execution context.
///
/// During a pipeline execution, context will be passed from the function starting the
/// pipeline down to each pipeline policy. Contrarily to the Request, the context can be mutated
/// by each pipeline policy and is not reset between retries. It can be used to pass the whole
/// pipeline execution history between policies.
/// For example, it could be used to signal that an execution failed because a CosmosDB endpoint is
/// down and the appropriate policy should try the next one).
#[derive(Clone)]
pub struct Context {
    // Temporary hack to make sure that Context is not initializeable
    // Soon Context will have proper data fields
    _priv: (),
    bag: HashMap<&'static str, Arc<dyn Bag>>,
}

impl Context {
    pub fn new() -> Self {
        Self {
            _priv: (),
            bag: HashMap::new(),
        }
    }

    pub fn get_from_bag(&self, k: &str) -> Option<&Arc<dyn Bag>> {
        self.bag.get(k)
    }

    pub fn insert_into_bag(&mut self, k: &'static str, v: Arc<dyn Bag>) -> Option<Arc<dyn Bag>> {
        self.bag.insert(k, v)
    }
}
