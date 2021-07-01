use crate::headers::{HEADER_DATE, HEADER_VERSION};
use crate::resources::permission::AuthorizationToken;
use crate::resources::ResourceType;
use azure_core::{Context, Policy, PolicyResult, Request, Response};
use http::header::AUTHORIZATION;
use http::HeaderValue;
use ring::hmac;
use std::borrow::Cow;
use std::sync::Arc;
use url::form_urlencoded;

const TIME_FORMAT: &str = "%a, %d %h %Y %T GMT";
const AZURE_VERSION: &str = "2018-12-31";
const VERSION: &str = "1.0";

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
        println!("called AuthorizationPolicy::send. self == {:#?}", self);

        if next.is_empty() {
            return Err(Box::new(azure_core::PipelineError::InvalidTailPolicy(
                Box::new(self.clone()),
            )));
        }

        let resource_type = {
            let resource_type = ctx
                .get_from_bag("resource_type")
                .expect("SDK bug: bag item resource_type must be set before starting the pipeline");

            resource_type
                .downcast_ref::<ResourceType>()
                .expect("SDK bug: bag item called resource_type must be of type ResourceType")
                .to_owned()
        };
        println!("obtained resource type == {:?}", resource_type);

        let time = format!("{}", chrono::Utc::now().format(TIME_FORMAT));

        let uri_path = &request.uri().path_and_query().unwrap().to_string()[1..];
        println!("uri_path == {:#?}", uri_path);

        let auth = {
            let resource_link = generate_resource_link(&uri_path);
            println!("resource_link_new == {}", resource_link);
            generate_authorization(
                &self.authorization_token,
                &request.method(),
                &resource_type,
                resource_link,
                &time,
            )
        };

        println!("about to add {} == {}", AUTHORIZATION, &auth);

        // add the headers
        // TODO: remove this when no longer necessary
        request.headers_mut().remove(HEADER_DATE);
        request.headers_mut().remove(HEADER_VERSION);
        request.headers_mut().remove(AUTHORIZATION);

        request
            .headers_mut()
            .append(HEADER_DATE, HeaderValue::from_str(&time)?);
        request
            .headers_mut()
            .append(HEADER_VERSION, HeaderValue::from_static(AZURE_VERSION));
        request
            .headers_mut()
            .append(AUTHORIZATION, HeaderValue::from_str(&auth)?);

        println!("\n\nrequest =={:?}", request);

        // now next[0] is safe (will not panic) because of the above check
        next[0].send(ctx, request, &next[1..]).await
    }
}

fn generate_resource_link(u: &str) -> &str {
    static ENDING_STRINGS: &[&str] = &[
        "dbs",
        "colls",
        "docs",
        "sprocs",
        "users",
        "permissions",
        "attachments",
        "pkranges",
        "udfs",
        "triggers",
    ];

    // store the element only if it does not end with dbs, colls or docs
    let p = u;
    let len = p.len();
    for str_to_match in ENDING_STRINGS {
        let end_len = str_to_match.len();

        if end_len <= len {
            let end_offset = len - end_len;
            let sm = &p[end_offset..];
            if sm == *str_to_match {
                if len == end_len {
                    return "";
                }

                if &p[end_offset - 1..end_offset] == "/" {
                    let ret = &p[0..len - end_len - 1];
                    return ret;
                }
            }
        }
    }
    p
}

fn generate_authorization(
    auth_token: &AuthorizationToken,
    http_method: &http::Method,
    resource_type: &ResourceType,
    resource_link: &str,
    time: &str,
) -> String {
    let string_to_sign = string_to_sign(http_method, resource_type, resource_link, time);
    debug!(
        "generate_authorization::string_to_sign == {:?}",
        string_to_sign
    );

    let str_unencoded = format!(
        "type={}&ver={}&sig={}",
        match auth_token {
            AuthorizationToken::Primary(_) => "master",
            AuthorizationToken::Resource(_) => "resource",
        },
        VERSION,
        match auth_token {
            AuthorizationToken::Primary(key) =>
                Cow::Owned(encode_str_to_sign(&string_to_sign, key)),
            AuthorizationToken::Resource(key) => Cow::Borrowed(key),
        },
    );
    debug!(
        "generate_authorization::str_unencoded == {:?}",
        str_unencoded
    );

    form_urlencoded::byte_serialize(&str_unencoded.as_bytes()).collect::<String>()
}

fn string_to_sign(
    http_method: &http::Method,
    rt: &ResourceType,
    resource_link: &str,
    time: &str,
) -> String {
    // From official docs:
    // StringToSign =
    //      Verb.toLowerCase() + "\n" +
    //      ResourceType.toLowerCase() + "\n" +
    //      ResourceLink + "\n" +
    //      Date.toLowerCase() + "\n" +
    //      "" + "\n";
    // Notice the empty string at the end so we need to add two new lines

    format!(
        "{}\n{}\n{}\n{}\n\n",
        match *http_method {
            http::Method::GET => "get",
            http::Method::PUT => "put",
            http::Method::POST => "post",
            http::Method::DELETE => "delete",
            http::Method::HEAD => "head",
            http::Method::TRACE => "trace",
            http::Method::OPTIONS => "options",
            http::Method::CONNECT => "connect",
            http::Method::PATCH => "patch",
            _ => "extension",
        },
        match rt {
            ResourceType::Databases => "dbs",
            ResourceType::Collections => "colls",
            ResourceType::Documents => "docs",
            ResourceType::StoredProcedures => "sprocs",
            ResourceType::Users => "users",
            ResourceType::Permissions => "permissions",
            ResourceType::Attachments => "attachments",
            ResourceType::PartitionKeyRanges => "pkranges",
            ResourceType::UserDefinedFunctions => "udfs",
            ResourceType::Triggers => "triggers",
        },
        resource_link,
        time.to_lowercase()
    )
}

fn encode_str_to_sign(str_to_sign: &str, key: &[u8]) -> String {
    let key = hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let sig = hmac::sign(&key, str_to_sign.as_bytes());
    base64::encode(sig.as_ref())
}
