// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::types::Address;
use crate::types::Bytes;
use cita_cloud_proto::executor::CallRequest as CloudCallRequest;
use libproto::request::Call;

/// Call request
#[derive(Debug, Default, Eq, PartialEq)]
pub struct CallRequest {
    /// From
    pub from: Option<Address>,
    /// To
    pub to: Address,
    /// Data
    pub data: Option<Bytes>,
    /// Height
    pub height: Option<u64>,
}

impl From<Call> for CallRequest {
    fn from(call: Call) -> Self {
        CallRequest {
            from: if call.get_from().is_empty() {
                None
            } else {
                Some(Address::from_slice(call.get_from()))
            },
            to: Address::from_slice(call.get_to()),
            data: if call.data.is_empty() {
                None
            } else {
                Some(call.data)
            },
            height: if let Ok(height) = call.height.parse::<u64>() {
                Some(height)
            } else {
                None
            },
        }
    }
}

impl From<CloudCallRequest> for CallRequest {
    fn from(call: CloudCallRequest) -> Self {
        CallRequest {
            from: if call.from.is_empty() {
                None
            } else {
                Some(Address::from_slice(call.from.as_slice()))
            },
            to: Address::from_slice(call.to.as_slice()),
            data: if call.method.is_empty() {
                None
            } else {
                Some(call.method)
            },
            height: if call.height == 0 {
                None
            } else {
                Some(call.height)
            },
        }
    }
}

#[cfg(test)]
mod tests {}
