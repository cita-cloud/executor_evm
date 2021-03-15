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

// Define all Reserved Addresses.
// # Builtin
//
// # Ethreum builtin
//
// ecrecover: 0x0000000000000000000000000000000000000001
// sha256:    0x0000000000000000000000000000000000000002
// ripemd160: 0x0000000000000000000000000000000000000003
// identity:  0x0000000000000000000000000000000000000004
//
// # CITA builtin
//
// edrecover: 0x0000000000000000000000000000000000ff0001
//
// # All
//
//     Start: 0xffffffffffffffffffffffffffffffffff000000
//     End  : 0xffffffffffffffffffffffffffffffffffffffff
//
// ## Action Address:
//
//     Start: 0xffffffffffffffffffffffffffffffffff010000
//     End  : 0xffffffffffffffffffffffffffffffffff01ffff
//
// ### Normal Action Address
//
//     Start: 0xffffffffffffffffffffffffffffffffff010000
//     End  : 0xffffffffffffffffffffffffffffffffff0100ff
//
// ### Go Action Address
//
//     Start: 0xffffffffffffffffffffffffffffffffff018000
//     End  : 0xffffffffffffffffffffffffffffffffff018fff
//
// ## System Contracts
//
//     Start: 0xffffffffffffffffffffffffffffffffff020000
//     End  : 0xffffffffffffffffffffffffffffffffff02ffff
//
// ### Normal System Contracts
//
//     Start: 0xffffffffffffffffffffffffffffffffff020000
//     End  : 0xffffffffffffffffffffffffffffffffff0200ff
//
// ### Permission System Contracts
//
//     Start: 0xffffffffffffffffffffffffffffffffff021000
//     End  : 0xffffffffffffffffffffffffffffffffff0210ff
//
// ## Native Contracts
//
//     Start: 0xffffffffffffffffffffffffffffffffff030000
//     End  : 0xffffffffffffffffffffffffffffffffff03ffff
//

// Ethereum builtin address
pub const ECRECOVER_ADDRESS: &str = "0000000000000000000000000000000000000001";
pub const SHA256_ADDRESS: &str = "0000000000000000000000000000000000000002";
pub const RIPEMD160_ADDRESS: &str = "0000000000000000000000000000000000000003";
pub const IDENTITY_ADDRESS: &str = "0000000000000000000000000000000000000004";

// CITA builtin address
pub const EDRECOVER_ADDRESS: &str = "0000000000000000000000000000000000ff0001";

// Normal Action Address
pub const STORE_ADDRESS: &str = "ffffffffffffffffffffffffffffffffff010000";
pub const ABI_ADDRESS: &str = "ffffffffffffffffffffffffffffffffff010001";
pub const AMEND_ADDRESS: &str = "ffffffffffffffffffffffffffffffffff010002";
// Normal System Contracts
pub const SYS_CONFIG: &str = "ffffffffffffffffffffffffffffffffff020000";
pub const NODE_MANAGER: &str = "ffffffffffffffffffffffffffffffffff020001";
pub const CHAIN_MANAGER: &str = "ffffffffffffffffffffffffffffffffff020002";
pub const QUOTA_MANAGER: &str = "ffffffffffffffffffffffffffffffffff020003";
pub const PERMISSION_MANAGEMENT: &str = "ffffffffffffffffffffffffffffffffff020004";
pub const PERMISSION_CREATOR: &str = "ffffffffffffffffffffffffffffffffff020005";
pub const AUTHORIZATION: &str = "ffffffffffffffffffffffffffffffffff020006";
pub const ROLE_MANAGEMENT: &str = "ffffffffffffffffffffffffffffffffff020007";
pub const ROLE_CREATOR: &str = "ffffffffffffffffffffffffffffffffff020008";
pub const GROUP: &str = "ffffffffffffffffffffffffffffffffff020009";
pub const GROUP_MANAGEMENT: &str = "ffffffffffffffffffffffffffffffffff02000a";
pub const GROUP_CREATOR: &str = "ffffffffffffffffffffffffffffffffff02000b";
pub const ADMIN: &str = "ffffffffffffffffffffffffffffffffff02000c";
pub const ROLE_AUTH: &str = "ffffffffffffffffffffffffffffffffff02000d";
pub const BATCH_TX: &str = "ffffffffffffffffffffffffffffffffff02000e";
pub const EMERGENCY_INTERVENTION: &str = "ffffffffffffffffffffffffffffffffff02000f";
pub const PRICE_MANAGEMENT: &str = "ffffffffffffffffffffffffffffffffff020010";
pub const VERSION_MANAGEMENT: &str = "ffffffffffffffffffffffffffffffffff020011";
pub const ALL_GROUPS: &str = "ffffffffffffffffffffffffffffffffff020012";
pub const AUTO_EXEC: &str = "ffffffffffffffffffffffffffffffffff020013";
pub const CERT_REVOKE_MANAGER: &str = "ffffffffffffffffffffffffffffffffff020030";
pub const ALLOWANCE_MANAGEMENT: &str = "ffffffffffffffffffffffffffffffffff020040";
pub const ALLOWANCE: &str = "ffffffffffffffffffffffffffffffffff020041";
// Permission System Contracts
pub const PERMISSION_SEND_TX: &str = "ffffffffffffffffffffffffffffffffff021000";
pub const PERMISSION_CREATE_CONTRACT: &str = "ffffffffffffffffffffffffffffffffff021001";
pub const PERMISSION_NEW_PERMISSION: &str = "ffffffffffffffffffffffffffffffffff021010";
pub const PERMISSION_DELETE_PERMISSION: &str = "ffffffffffffffffffffffffffffffffff021011";
pub const PERMISSION_UPDATE_PERMISSION: &str = "ffffffffffffffffffffffffffffffffff021012";
pub const PERMISSION_SET_AUTH: &str = "ffffffffffffffffffffffffffffffffff021013";
pub const PERMISSION_CANCEL_AUTH: &str = "ffffffffffffffffffffffffffffffffff021014";
pub const PERMISSION_NEW_ROLE: &str = "ffffffffffffffffffffffffffffffffff021015";
pub const PERMISSION_DELETE_ROLE: &str = "ffffffffffffffffffffffffffffffffff021016";
pub const PERMISSION_UPDATE_ROLE: &str = "ffffffffffffffffffffffffffffffffff021017";
pub const PERMISSION_SET_ROLE: &str = "ffffffffffffffffffffffffffffffffff021018";
pub const PERMISSION_CANCEL_ROLE: &str = "ffffffffffffffffffffffffffffffffff021019";
pub const PERMISSION_NEW_GROUP: &str = "ffffffffffffffffffffffffffffffffff02101a";
pub const PERMISSION_DELETE_GROUP: &str = "ffffffffffffffffffffffffffffffffff02101b";
pub const PERMISSION_UPDATE_GROUP: &str = "ffffffffffffffffffffffffffffffffff02101c";
pub const PERMISSION_NEW_NODE: &str = "ffffffffffffffffffffffffffffffffff021020";
pub const PERMISSION_DELETE_NODE: &str = "ffffffffffffffffffffffffffffffffff021021";
pub const PERMISSION_UPDATE_NODE: &str = "ffffffffffffffffffffffffffffffffff021022";
pub const PERMISSION_ACCOUNT_QUOTA: &str = "ffffffffffffffffffffffffffffffffff021023";
pub const PERMISSION_BLOCK_QUOTA: &str = "ffffffffffffffffffffffffffffffffff021024";
pub const PERMISSION_BATCH_TX: &str = "ffffffffffffffffffffffffffffffffff021025";
pub const PERMISSION_EMERGENCY_INTERVENTION: &str = "ffffffffffffffffffffffffffffffffff021026";
pub const PERMISSION_QUOTA_PRICE: &str = "ffffffffffffffffffffffffffffffffff021027";
pub const PERMISSION_VERSION: &str = "ffffffffffffffffffffffffffffffffff021028";
pub const PERMISSION_UPDATE_ALLOWANCE: &str = "ffffffffffffffffffffffffffffffffff021029";
// Native Contracts
pub const NATIVE_SIMPLE_STORAGE: &str = "ffffffffffffffffffffffffffffffffff030000";
pub const NATIVE_ZK_PRIVACY: &str = "ffffffffffffffffffffffffffffffffff030001";
pub const NATIVE_CROSS_CHAIN_VERIFY: &str = "ffffffffffffffffffffffffffffffffff030002";
