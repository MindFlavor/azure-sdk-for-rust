#![doc = "generated by AutoRust 0.1.0"]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ReservationStatusCode {
    None,
    Pending,
    Active,
    PurchaseError,
    PaymentInstrumentError,
    Split,
    Merged,
    Expired,
    Succeeded,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ErrorResponseCode {
    NotSpecified,
    InternalServerError,
    ServerTimeout,
    AuthorizationFailed,
    BadRequest,
    ClientCertificateThumbprintNotSet,
    InvalidRequestContent,
    OperationFailed,
    HttpMethodNotSupported,
    InvalidRequestUri,
    MissingTenantId,
    InvalidTenantId,
    InvalidReservationOrderId,
    InvalidReservationId,
    ReservationIdNotInReservationOrder,
    ReservationOrderNotFound,
    InvalidSubscriptionId,
    InvalidAccessToken,
    InvalidLocationId,
    UnauthenticatedRequestsThrottled,
    InvalidHealthCheckType,
    Forbidden,
    BillingScopeIdCannotBeChanged,
    AppliedScopesNotAssociatedWithCommerceAccount,
    AppliedScopesSameAsExisting,
    RoleAssignmentCreationFailed,
    ReservationOrderCreationFailed,
    ReservationOrderNotEnabled,
    CapacityUpdateScopesFailed,
    UnsupportedReservationTerm,
    ReservationOrderIdAlreadyExists,
    RiskCheckFailed,
    CreateQuoteFailed,
    ActivateQuoteFailed,
    NonsupportedAccountId,
    PaymentInstrumentNotFound,
    MissingAppliedScopesForSingle,
    NoValidReservationsToReRate,
    #[serde(rename = "ReRateOnlyAllowedForEA")]
    ReRateOnlyAllowedForEa,
    OperationCannotBePerformedInCurrentState,
    InvalidSingleAppliedScopesCount,
    InvalidFulfillmentRequestParameters,
    NotSupportedCountry,
    InvalidRefundQuantity,
    PurchaseError,
    BillingCustomerInputError,
    BillingPaymentInstrumentSoftError,
    BillingPaymentInstrumentHardError,
    BillingTransientError,
    BillingError,
    FulfillmentConfigurationError,
    FulfillmentOutOfStockError,
    FulfillmentTransientError,
    FulfillmentError,
    CalculatePriceFailed,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ProvisioningState {
    Creating,
    PendingResourceHold,
    ConfirmedResourceHold,
    PendingBilling,
    ConfirmedBilling,
    Created,
    Succeeded,
    Cancelled,
    Expired,
    BillingFailed,
    Failed,
    Split,
    Merged,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Location {
    #[serde(rename = "westus")]
    Westus,
    #[serde(rename = "eastus")]
    Eastus,
    #[serde(rename = "eastus2")]
    Eastus2,
    #[serde(rename = "northcentralus")]
    Northcentralus,
    #[serde(rename = "westus2")]
    Westus2,
    #[serde(rename = "southcentralus")]
    Southcentralus,
    #[serde(rename = "centralus")]
    Centralus,
    #[serde(rename = "westeurope")]
    Westeurope,
    #[serde(rename = "northeurope")]
    Northeurope,
    #[serde(rename = "eastasia")]
    Eastasia,
    #[serde(rename = "southeastasia")]
    Southeastasia,
    #[serde(rename = "japaneast")]
    Japaneast,
    #[serde(rename = "japanwest")]
    Japanwest,
    #[serde(rename = "brazilsouth")]
    Brazilsouth,
    #[serde(rename = "australiaeast")]
    Australiaeast,
    #[serde(rename = "australiasoutheast")]
    Australiasoutheast,
    #[serde(rename = "southindia")]
    Southindia,
    #[serde(rename = "westindia")]
    Westindia,
    #[serde(rename = "centralindia")]
    Centralindia,
    #[serde(rename = "canadacentral")]
    Canadacentral,
    #[serde(rename = "canadaeast")]
    Canadaeast,
    #[serde(rename = "uksouth")]
    Uksouth,
    #[serde(rename = "westcentralus")]
    Westcentralus,
    #[serde(rename = "ukwest")]
    Ukwest,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkuName {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(rename = "resourceType", skip_serializing)]
    pub resource_type: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(skip_serializing)]
    pub tier: Option<String>,
    #[serde(skip_serializing)]
    pub size: Option<String>,
    #[serde(skip_serializing)]
    pub terms: Vec<ReservationTerm>,
    #[serde(skip_serializing)]
    pub locations: Vec<String>,
    #[serde(skip_serializing)]
    pub capabilities: Vec<SkuCapability>,
    #[serde(skip_serializing)]
    pub restrictions: Vec<SkuRestriction>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkuCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkuRestriction {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(rename = "reasonCode", skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservationOrderResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<i64>,
    #[serde(skip_serializing)]
    pub id: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<ReservationOrderProperties>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ReservationTerm {
    #[serde(rename = "P1Y")]
    P1y,
    #[serde(rename = "P3Y")]
    P3y,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservationOrderProperties {
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "requestDateTime", skip_serializing_if = "Option::is_none")]
    pub request_date_time: Option<String>,
    #[serde(rename = "createdDateTime", skip_serializing_if = "Option::is_none")]
    pub created_date_time: Option<String>,
    #[serde(rename = "expiryDate", skip_serializing_if = "Option::is_none")]
    pub expiry_date: Option<String>,
    #[serde(rename = "originalQuantity", skip_serializing_if = "Option::is_none")]
    pub original_quantity: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub term: Option<ReservationTerm>,
    #[serde(rename = "provisioningState", skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reservations: Vec<ReservationResponse>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<i64>,
    #[serde(skip_serializing)]
    pub id: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<reservation_response::Kind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sku: Option<SkuName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<ReservationProperties>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
}
pub mod reservation_response {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Kind {
        #[serde(rename = "Microsoft.Compute")]
        Microsoft_Compute,
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservationProperties {
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "appliedScopes", skip_serializing_if = "Option::is_none")]
    pub applied_scopes: Option<AppliedScopes>,
    #[serde(rename = "appliedScopeType", skip_serializing_if = "Option::is_none")]
    pub applied_scope_type: Option<AppliedScopeType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<i32>,
    #[serde(rename = "provisioningState", skip_serializing_if = "Option::is_none")]
    pub provisioning_state: Option<ProvisioningState>,
    #[serde(rename = "effectiveDateTime", skip_serializing_if = "Option::is_none")]
    pub effective_date_time: Option<String>,
    #[serde(rename = "lastUpdatedDateTime", skip_serializing)]
    pub last_updated_date_time: Option<String>,
    #[serde(rename = "expiryDate", skip_serializing_if = "Option::is_none")]
    pub expiry_date: Option<String>,
    #[serde(rename = "extendedStatusInfo", skip_serializing_if = "Option::is_none")]
    pub extended_status_info: Option<ExtendedStatusInfo>,
    #[serde(rename = "splitProperties", skip_serializing_if = "Option::is_none")]
    pub split_properties: Option<ReservationSplitProperties>,
    #[serde(rename = "mergeProperties", skip_serializing_if = "Option::is_none")]
    pub merge_properties: Option<ReservationMergeProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservationSplitProperties {
    #[serde(rename = "splitDestinations", skip_serializing_if = "Vec::is_empty")]
    pub split_destinations: Vec<String>,
    #[serde(rename = "splitSource", skip_serializing_if = "Option::is_none")]
    pub split_source: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservationMergeProperties {
    #[serde(rename = "mergeDestination", skip_serializing_if = "Option::is_none")]
    pub merge_destination: Option<String>,
    #[serde(rename = "mergeSources", skip_serializing_if = "Vec::is_empty")]
    pub merge_sources: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PatchProperties {
    #[serde(rename = "appliedScopeType", skip_serializing_if = "Option::is_none")]
    pub applied_scope_type: Option<AppliedScopeType>,
    #[serde(rename = "appliedScopes", skip_serializing_if = "Option::is_none")]
    pub applied_scopes: Option<AppliedScopes>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SplitProperties {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub quantities: Vec<i64>,
    #[serde(rename = "reservationId", skip_serializing_if = "Option::is_none")]
    pub reservation_id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MergeProperties {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MergeRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<MergeProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Patch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<PatchProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SplitRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SplitProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Error {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ExtendedErrorInfo>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExtendedErrorInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<ErrorResponseCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExtendedStatusInfo {
    #[serde(rename = "statusCode", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<ReservationStatusCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservationOrderList {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<ReservationOrderResponse>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReservationList {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<ReservationResponse>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppliedReservations {
    #[serde(skip_serializing)]
    pub id: Option<String>,
    #[serde(skip_serializing)]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing)]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<AppliedReservationsProperties>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppliedReservationsProperties {
    #[serde(rename = "reservationOrderIds", skip_serializing_if = "Option::is_none")]
    pub reservation_order_ids: Option<AppliedReservationList>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppliedReservationList {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<String>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationList {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value: Vec<OperationResponse>,
    #[serde(rename = "nextLink", skip_serializing_if = "Option::is_none")]
    pub next_link: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<OperationDisplay>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationDisplay {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AppliedScopeType {
    Single,
    Shared,
}
pub type AppliedScopes = Vec<String>;