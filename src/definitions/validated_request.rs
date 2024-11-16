use crate::{definitions::ValidationErrors, presentation::device::RequestedItems};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
pub struct ValidatedRequest {
    pub items_request: RequestedItems,
    pub common_name: Option<String>,
    pub reader_authentication: Status,
    pub errors: ValidationErrors,
}

#[derive(Serialize, Deserialize, Default)]
pub enum Status {
    #[default]
    Unchecked,
    Invalid,
    Valid,
}
