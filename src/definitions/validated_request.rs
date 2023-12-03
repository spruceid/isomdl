use serde::{Deserialize, Serialize};
use crate::{definitions::ValidationErrors, presentation::device::RequestedItems};

#[derive(Serialize, Deserialize)]
pub struct ValidatedRequest {
    pub items_requests: RequestedItems,
    pub common_name: Option<String>,
    pub reader_authentication: Status,
    pub errors: ValidationErrors,
}


#[derive(Serialize, Deserialize)]
pub enum Status {
    Unchecked,
    Invalid,
    Valid,
}
