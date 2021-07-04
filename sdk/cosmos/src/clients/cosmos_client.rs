use super::DatabaseClient;
use crate::authorization_policy::CosmosContext;
use crate::headers::*;
use crate::operations::*;
use crate::resources::permission::AuthorizationToken;
use crate::resources::ResourceType;
use crate::{requests, ReadonlyString};

use azure_core::pipeline::Pipeline;
use azure_core::Context;
use azure_core::HttpClient;
use azure_core::Request;
use azure_core::*;
use http::request::Builder as RequestBuilder;
use http::{header, HeaderValue};
use ring::hmac;
use url::form_urlencoded;

use std::borrow::Cow;
use std::fmt::Debug;
use std::sync::Arc;

/// The well-known account key used by Azure Cosmos DB Emulator.
/// https://docs.microsoft.com/azure/cosmos-db/local-emulator?tabs=ssl-netstd21#connect-with-emulator-apis
pub const EMULATOR_ACCOUNT_KEY: &str =
    "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==";

const AZURE_VERSION: &str = "2018-12-31";
const VERSION: &str = "1.0";
const TIME_FORMAT: &str = "%a, %d %h %Y %T GMT";

/// A plain Cosmos client.
#[derive(Debug, Clone)]
pub struct CosmosClient {
    pipeline: Pipeline<CosmosContext>,
    auth_token: AuthorizationToken,
    cloud_location: CloudLocation,
}

/// Options for specifying how a Cosmos client will behave
#[derive(Debug, Clone, Default)]
pub struct CosmosOptions {
    options: ClientOptions<CosmosContext>,
}

impl CosmosOptions {
    /// Create options based on the provided http client
    pub fn with_client(client: Arc<dyn HttpClient>) -> Self {
        Self {
            options: ClientOptions::default()
                .retry(RetryOptions::default().mode(RetryMode::Fixed))
                .transport(TransportOptions::new(client)),
        }
    }
}

/// Create a Pipeline from CosmosOptions
fn new_pipeline_from_options(
    options: CosmosOptions,
    authorization_token: AuthorizationToken,
) -> Pipeline<CosmosContext> {
    let auth_policy: Arc<dyn azure_core::Policy<CosmosContext>> =
        Arc::new(crate::AuthorizationPolicy::new(authorization_token));

    let mut per_retry_policies = Vec::with_capacity(1);
    // take care of adding the AuthorizationPolicy as **last** retry policy.
    // Policies can change the url and/or the headers and the AuthorizationPolicy
    // must be able to inspect them or the resulting token will be invalid.
    per_retry_policies.push(auth_policy);

    Pipeline::new(
        option_env!("CARGO_PKG_NAME"),
        option_env!("CARGO_PKG_VERSION"),
        &options.options,
        Vec::new(),
        per_retry_policies,
    )
}

impl CosmosClient {
    /// Create a new `CosmosClient` which connects to the account's instance in the public Azure cloud.
    pub fn new(account: String, auth_token: AuthorizationToken, options: CosmosOptions) -> Self {
        let cloud_location = CloudLocation::Public(account);
        // TODO: The AuthorizationToken will only be stored in the pipeline via its policy.
        // Right now the AuthorizationToken is a field of the Client.
        // This will be corrected once every Cosmos function has been be migrated to the pipeline.
        // Once that happens, we will remove the clone below.
        let pipeline = new_pipeline_from_options(options, auth_token.clone());
        Self {
            pipeline,
            auth_token,
            cloud_location,
        }
    }

    /// Create a new `CosmosClient` which connects to the account's instance in the Chinese Azure cloud.
    pub fn new_china(
        account: String,
        auth_token: AuthorizationToken,
        options: CosmosOptions,
    ) -> Self {
        let cloud_location = CloudLocation::China(account);
        let pipeline = new_pipeline_from_options(options, auth_token.clone());
        Self {
            pipeline,
            auth_token,
            cloud_location,
        }
    }

    /// Create a new `CosmosClient` which connects to the account's instance in custom Azure cloud.
    pub fn new_custom(
        account: String,
        auth_token: AuthorizationToken,
        uri: String,
        options: CosmosOptions,
    ) -> Self {
        let cloud_location = CloudLocation::Custom { account, uri };
        let pipeline = new_pipeline_from_options(options, auth_token.clone());
        Self {
            pipeline,
            auth_token,
            cloud_location,
        }
    }

    /// Create a new `CosmosClient` which connects to the account's instance in Azure emulator
    pub fn new_emulator(address: &str, port: u16, options: CosmosOptions) -> Self {
        let auth_token = AuthorizationToken::primary_from_base64(EMULATOR_ACCOUNT_KEY).unwrap();
        let uri = format!("https://{}:{}", address, port);
        let cloud_location = CloudLocation::Custom {
            account: String::from("Custom"),
            uri,
        };
        let pipeline = new_pipeline_from_options(options, auth_token.clone());
        Self {
            pipeline,
            auth_token,
            cloud_location,
        }
    }

    /// Set the auth token used
    pub fn auth_token(&mut self, auth_token: AuthorizationToken) {
        self.auth_token = auth_token;
    }

    /// Create a database
    pub async fn create_database<S: AsRef<str>, R>(
        &self,
        //ctx: Context<R>, // I do not understand why the Context should be passes by the caller.
        // Isn't options the right field to customize the call? I have disabled the parameter for
        // the time being to simplify the API.
        database_name: S,
        options: CreateDatabaseOptions,
    ) -> Result<CreateDatabaseResponse, crate::Error>
    where
        R: Send + Sync,
    {
        let mut request = self.prepare_request2("dbs", http::Method::POST, ResourceType::Databases);

        let mut cosmos_context = Context::new(CosmosContext {
            resource_type: ResourceType::Databases,
        });

        options.decorate_request(&mut request, database_name.as_ref())?;
        let response = self
            .pipeline()
            .send(&mut cosmos_context, &mut request)
            .await?
            .validate(http::StatusCode::CREATED)
            .await?;

        Ok(CreateDatabaseResponse::try_from(response).await?)
    }

    pub(crate) fn pipeline(&self) -> &Pipeline<CosmosContext> {
        &self.pipeline
    }

    /// List all databases
    pub fn list_databases(&self) -> requests::ListDatabasesBuilder<'_> {
        requests::ListDatabasesBuilder::new(self)
    }

    /// Convert into a [`DatabaseClient`]
    pub fn into_database_client<S: Into<ReadonlyString>>(self, database_name: S) -> DatabaseClient {
        DatabaseClient::new(self, database_name)
    }

    /// Prepares an `http::RequestBuilder`.
    ///
    /// TODO: Remove once all operations have been moved to pipeline architecture. This is used by
    /// legacy operations that have not moved to the use of the pipeline architecture. Once
    /// that is complete, this will be superceded by `prepare_request2`.
    pub(crate) fn prepare_request(
        &self,
        uri_path: &str,
        http_method: http::Method,
        resource_type: ResourceType,
    ) -> RequestBuilder {
        let time = format!("{}", chrono::Utc::now().format(TIME_FORMAT));

        let auth = {
            let resource_link = generate_resource_link(&uri_path);
            println!("resource_link_old == {}", resource_link);
            generate_authorization(
                &self.auth_token,
                &http_method,
                resource_type,
                resource_link,
                &time,
            )
        };
        self.prepare_request_with_signature(uri_path, http_method, &time, &auth)
    }

    /// Prepares' an `azure_core::Request`.
    ///
    /// Note: Eventually this method will replace `prepare_request` fully
    pub(crate) fn prepare_request2(
        &self,
        uri_path: &str,
        http_method: http::Method,
        resource_type: ResourceType,
    ) -> Request {
        let builder = self.prepare_request(uri_path, http_method, resource_type);
        builder.body(bytes::Bytes::new()).unwrap().into()
    }

    pub(crate) fn http_client(&self) -> &dyn HttpClient {
        self.pipeline.http_client()
    }

    fn prepare_request_with_signature(
        &self,
        uri_path: &str,
        http_method: http::Method,
        time: &str,
        signature: &str,
    ) -> RequestBuilder {
        trace!("prepare_request::auth == {:?}", signature);
        let uri = format!("{}/{}", self.cloud_location.url(), uri_path);
        debug!(
            "cosmos::client::prepare_request_with_resource_signature::uri == {:?}",
            uri
        );

        RequestBuilder::new()
            .method(http_method)
            .uri(uri)
            .header(HEADER_DATE, time)
            .header(HEADER_VERSION, HeaderValue::from_static(AZURE_VERSION))
            .header(header::AUTHORIZATION, signature)
    }
}

fn generate_authorization(
    auth_token: &AuthorizationToken,
    http_method: &http::Method,
    resource_type: ResourceType,
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

fn encode_str_to_sign(str_to_sign: &str, key: &[u8]) -> String {
    let key = hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let sig = hmac::sign(&key, str_to_sign.as_bytes());
    base64::encode(sig.as_ref())
}

fn string_to_sign(
    http_method: &http::Method,
    rt: ResourceType,
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

/// The cloud with which you want to interact.
///
/// All variants require the cosmos account name. `Custom` also requires a valid
/// base URL (e.g. https://custom.documents.azure.com)
#[derive(Debug, Clone)]
enum CloudLocation {
    /// Azure public cloud
    Public(String),
    /// Azure China cloud
    China(String),
    // TODO: Other govt clouds?
    /// A custom base URL
    Custom { account: String, uri: String },
}

impl CloudLocation {
    /// the base URL for a given cloud location
    fn url(&self) -> String {
        match self {
            CloudLocation::Public(account) => format!("https://{}.documents.azure.com", account),
            CloudLocation::China(account) => format!("https://{}.documents.azure.cn", account),
            CloudLocation::Custom { uri, .. } => uri.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_to_sign_00() {
        let time =
            chrono::DateTime::parse_from_rfc3339("1900-01-01T01:00:00.000000000+00:00").unwrap();
        let time = time.with_timezone(&chrono::Utc);
        let time = format!("{}", time.format(TIME_FORMAT));

        let ret = string_to_sign(
            &http::Method::GET,
            ResourceType::Databases,
            "dbs/MyDatabase/colls/MyCollection",
            &time,
        );
        assert_eq!(
            ret,
            "get
dbs
dbs/MyDatabase/colls/MyCollection
mon, 01 jan 1900 01:00:00 gmt

"
        );
    }

    #[test]
    fn generate_authorization_00() {
        let time =
            chrono::DateTime::parse_from_rfc3339("1900-01-01T01:00:00.000000000+00:00").unwrap();
        let time = time.with_timezone(&chrono::Utc);
        let time = format!("{}", time.format(TIME_FORMAT));

        let auth_token = AuthorizationToken::primary_from_base64(
            "8F8xXXOptJxkblM1DBXW7a6NMI5oE8NnwPGYBmwxLCKfejOK7B7yhcCHMGvN3PBrlMLIOeol1Hv9RCdzAZR5sg==",
        )
        .unwrap();

        let ret = generate_authorization(
            &auth_token,
            &http::Method::GET,
            ResourceType::Databases,
            "dbs/MyDatabase/colls/MyCollection",
            &time,
        );
        assert_eq!(
            ret,
            "type%3Dmaster%26ver%3D1.0%26sig%3DQkz%2Fr%2B1N2%2BPEnNijxGbGB%2FADvLsLBQmZ7uBBMuIwf4I%3D"
        );
    }

    #[test]
    fn generate_authorization_01() {
        let time =
            chrono::DateTime::parse_from_rfc3339("2017-04-27T00:51:12.000000000+00:00").unwrap();
        let time = time.with_timezone(&chrono::Utc);
        let time = format!("{}", time.format(TIME_FORMAT));

        let auth_token = AuthorizationToken::primary_from_base64(
            "dsZQi3KtZmCv1ljt3VNWNm7sQUF1y5rJfC6kv5JiwvW0EndXdDku/dkKBp8/ufDToSxL",
        )
        .unwrap();

        let ret = generate_authorization(
            &auth_token,
            &http::Method::GET,
            ResourceType::Databases,
            "dbs/ToDoList",
            &time,
        );

        // This is the result shown in the MSDN page. It's clearly wrong :)
        // below is the correct one.
        //assert_eq!(ret,
        //           "type%3dmaster%26ver%3d1.0%26sig%3dc09PEVJrgp2uQRkr934kFbTqhByc7TVr3O");

        assert_eq!(
            ret,
            "type%3Dmaster%26ver%3D1.0%26sig%3DKvBM8vONofkv3yKm%2F8zD9MEGlbu6jjHDJBp4E9c2ZZI%3D"
        );
    }

    #[test]
    fn generate_resource_link_00() {
        assert_eq!(generate_resource_link("dbs/second"), "dbs/second");
        assert_eq!(generate_resource_link("dbs"), "");
        assert_eq!(
            generate_resource_link("colls/second/third"),
            "colls/second/third"
        );
        assert_eq!(generate_resource_link("dbs/test_db/colls"), "dbs/test_db");
    }
}
