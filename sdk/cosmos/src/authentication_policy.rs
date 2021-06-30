use crate::resources::permission::AuthorizationToken;
use azure_core::{Context, Policy, PolicyResult, Request, Response};
use std::sync::Arc;

// We can implement Debug without leaking secrets because `AuthorizationToken`
// already masks the secure bits on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationPolicy {
    authorization_token: AuthorizationToken,
}

impl AuthenticationPolicy {
    pub(crate) fn new(authorization_token: AuthorizationToken) -> Self {
        Self {
            authorization_token,
        }
    }
}

#[async_trait::async_trait]
impl Policy for AuthenticationPolicy {
    async fn send(
        &self,
        ctx: &mut Context,
        request: &mut Request,
        next: &[Arc<dyn Policy>],
    ) -> PolicyResult<Response> {
        println!(
            "called AuthenticationPolicy send with {:#?}",
            self.authorization_token
        );

        // this will panic if there are no more following policies.
        next[0].send(ctx, request, &next[1..]).await
    }
}
