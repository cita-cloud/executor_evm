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

use cloud_util::common::read_toml;
use serde_derive::Deserialize;

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct ExecutorConfig {
    pub executor_port: u16,

    pub eth_compatibility: bool,

    pub db_path: String,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            executor_port: 50002,
            eth_compatibility: false,
            db_path: "data".to_string(),
        }
    }
}

impl ExecutorConfig {
    pub fn new(config_str: &str) -> Self {
        read_toml(config_str, "executor_evm")
    }
}

#[cfg(test)]
mod tests {
    use super::ExecutorConfig;

    #[test]
    fn basic_test() {
        let config = ExecutorConfig::new("example/config.toml");

        assert_eq!(config.executor_port, 50002);
    }
}
