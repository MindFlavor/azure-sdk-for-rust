/// Pipeline execution context.
///
/// During a pipeline execution, context will be passed from the function starting the
/// pipeline down to each pipeline policy. Contrarily to the Request, the context can be mutated
/// by each pipeline policy and is not reset between retries. It can be used to pass the whole
/// pipeline execution history between policies.
/// For example, it could be used to signal that an execution failed because a CosmosDB endpoint is
/// down and the appropriate policy should try the next one).
pub struct Context<R>
where
    R: Send + Sync,
{
    r: R,
}

impl<R> Context<R>
where
    R: Send + Sync,
{
    pub fn new(r: R) -> Self {
        Self { r }
    }

    pub fn set(&mut self, r: R) {
        self.r = r;
    }

    pub fn get(&self) -> &R {
        &self.r
    }
}
