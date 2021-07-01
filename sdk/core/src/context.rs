use std::any::Any;
use std::collections::HashMap;

/// Pipeline execution context.
///
/// During a pipeline execution, context will be passed from the function starting the
/// pipeline down to each pipeline policy. Contrarily to the Request, the context can be mutated
/// by each pipeline policy and is not reset between retries. It can be used to pass the whole
/// pipeline execution history between policies.
/// For example, it could be used to signal that an execution failed because a CosmosDB endpoint is
/// down and the appropriate policy should try the next one).
#[derive(Default)]
pub struct Context {
    bag: HashMap<&'static str, Box<dyn Any + Send + Sync>>,
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_from_bag(&self, k: &str) -> Option<&Box<dyn Any + Send + Sync>> {
        self.bag.get(k)
    }

    pub fn insert_into_bag(
        &mut self,
        k: &'static str,
        v: Box<dyn Any + Send + Sync>,
    ) -> Option<Box<dyn Any + Send + Sync>> {
        self.bag.insert(k, v)
    }
}
