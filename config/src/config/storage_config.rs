// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::utils;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

pub const TARGET_SNAPSHOT_SIZE: usize = 100_000;

/// Port selected RocksDB options for tuning underlying rocksdb instance of AptosDB.
/// see <https://github.com/facebook/rocksdb/blob/master/include/rocksdb/options.h>
/// for detailed explanations.
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RocksdbConfig {
    pub max_open_files: i32,
    pub max_total_wal_size: u64,
    pub max_background_jobs: i32,
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RocksdbConfigs {
    pub ledger_db_config: RocksdbConfig,
    pub state_merkle_db_config: RocksdbConfig,
    pub index_db_config: RocksdbConfig,
}

impl Default for RocksdbConfigs {
    fn default() -> Self {
        Self {
            ledger_db_config: RocksdbConfig {
                // Allow db to close old sst files, saving memory.
                max_open_files: 5000,
                // For now we set the max total WAL size to be 1G. This config can be useful when column
                // families are updated at non-uniform frequencies.
                max_total_wal_size: 1u64 << 30,
                // This includes threads for flashing and compaction. Rocksdb will decide the # of
                // threads to use internally.
                max_background_jobs: 16,
            },
            state_merkle_db_config: RocksdbConfig {
                // Allow db to close old sst files, saving memory.
                max_open_files: 5000,
                // For now we set the max total WAL size to be 1G. This config can be useful when column
                // families are updated at non-uniform frequencies.
                max_total_wal_size: 1u64 << 30,
                // This includes threads for flashing and compaction. Rocksdb will decide the # of
                // threads to use internally.
                max_background_jobs: 16,
            },
            index_db_config: RocksdbConfig {
                // Allow db to close old sst files, saving memory.
                max_open_files: 1000,
                // For now we set the max total WAL size to be 1G. This config can be useful when column
                // families are updated at non-uniform frequencies.
                max_total_wal_size: 1u64 << 30,
                // This includes threads for flashing and compaction. Rocksdb will decide the # of
                // threads to use internally.
                max_background_jobs: 16,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub address: SocketAddr,
    pub backup_service_address: SocketAddr,
    pub dir: PathBuf,
    pub storage_pruner_config: StoragePrunerConfig,
    #[serde(skip)]
    data_dir: PathBuf,
    /// The threshold that determine whether a snapshot should be committed to state merkle db.
    pub target_snapshot_size: usize,
    /// Rocksdb-specific configurations
    pub rocksdb_configs: RocksdbConfigs,
    /// Try to enable the internal indexer. The indexer expects to have seen all transactions
    /// since genesis. To recover operation after data loss, or to bootstrap a node in fast sync
    /// mode, the indexer db needs to be copied in from another node.
    pub enable_indexer: bool,
}

pub const NO_OP_STORAGE_PRUNER_CONFIG: StoragePrunerConfig = StoragePrunerConfig {
    enable_state_store_pruner: false,
    enable_ledger_pruner: false,
    state_store_prune_window: 0,
    ledger_prune_window: 0,
    ledger_pruning_batch_size: 10_000,
    state_store_pruning_batch_size: 10_000,
    user_pruning_window_offset: 0,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StoragePrunerConfig {
    /// Boolean to enable/disable the state store pruner. The state pruner is responsible for
    /// pruning state tree nodes.
    pub enable_state_store_pruner: bool,
    /// Boolean to enable/disable the ledger pruner. The ledger pruner is responsible for pruning
    /// everything else except for states (e.g. transactions, events etc.)
    pub enable_ledger_pruner: bool,
    /// The size of the window should be calculated based on disk space availability and system TPS.
    pub state_store_prune_window: u64,
    /// This is the default pruning window for any other store except for state store. State store
    /// being big in size, we might want to configure a smaller window for state store vs other
    /// store.
    pub ledger_prune_window: u64,
    /// Batch size of the versions to be sent to the ledger pruner - this is to avoid slowdown due to
    /// issuing too many DB calls and batch prune instead. For ledger pruner, this means the number
    /// of versions to prune a time.
    pub ledger_pruning_batch_size: usize,
    /// Similar to the variable above but for state store pruner. It means the number of stale
    /// nodes to prune a time.
    pub state_store_pruning_batch_size: usize,
    /// The offset for user pruning window to adjust
    pub user_pruning_window_offset: u64,
}

impl Default for StoragePrunerConfig {
    fn default() -> Self {
        StoragePrunerConfig {
            enable_state_store_pruner: true,
            enable_ledger_pruner: true,
            state_store_prune_window: 1_000_000,
            ledger_prune_window: 10_000_000,
            ledger_pruning_batch_size: 500,
            // A 10k transaction block (touching 60k state values, in the case of the account
            // creation benchmark) on a 4B items DB (or 1.33B accounts) yields 300k JMT nodes
            state_store_pruning_batch_size: 1_000,
            user_pruning_window_offset: 200_000,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> StorageConfig {
        StorageConfig {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6666),
            backup_service_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6186),
            dir: PathBuf::from("db"),
            // The prune window must at least out live a RPC request because its sub requests are
            // to return a consistent view of the DB at exactly same version. Considering a few
            // thousand TPS we are potentially going to achieve, and a few minutes a consistent view
            // of the DB might require, 10k (TPS)  * 100 (seconds)  =  1 Million might be a
            // conservatively safe minimal prune window. It'll take a few Gigabytes of disk space
            // depending on the size of an average account blob.
            storage_pruner_config: StoragePrunerConfig::default(),
            data_dir: PathBuf::from("/opt/aptos/data"),
            rocksdb_configs: RocksdbConfigs::default(),
            enable_indexer: false,
            target_snapshot_size: TARGET_SNAPSHOT_SIZE,
        }
    }
}

impl StorageConfig {
    pub fn dir(&self) -> PathBuf {
        if self.dir.is_relative() {
            self.data_dir.join(&self.dir)
        } else {
            self.dir.clone()
        }
    }

    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.data_dir = data_dir;
    }

    pub fn randomize_ports(&mut self) {
        self.address.set_port(utils::get_available_port());
        self.backup_service_address
            .set_port(utils::get_available_port());
    }
}
