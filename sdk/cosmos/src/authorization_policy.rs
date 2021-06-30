use crate::resources::permission::AuthorizationToken;
use azure_core::{Context, Policy, PolicyResult, Request, Response};
use std::sync::Arc;

// We can implement Debug without leaking secrets because `AuthorizationToken`
// already masks the secure bits on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationPolicy {
    authorization_token: AuthorizationToken,
}

impl AuthorizationPolicy {
    pub(crate) fn new(authorization_token: AuthorizationToken) -> Self {
        Self {
            authorization_token,
        }
    }
}

#[async_trait::async_trait]
impl Policy for AuthorizationPolicy {
    async fn send(
        &self,
        ctx: &mut Context,
        request: &mut Request,
        next: &[Arc<dyn Policy>],
    ) -> PolicyResult<Response> {
        println!(
            "called AuthorizationPolicy send with {:#?}",
            self.authorization_token
        );

        if next.is_empty() {
            return Err(Box::new(azure_core::PipelineError::InvalidTailPolicy(
                Box::new(self.clone()),
            )));
        }

        // now next[0] is safe (will not panic) because of the above check
        next[0].send(ctx, request, &next[1..]).await
    }
}
