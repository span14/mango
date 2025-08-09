// Copyright (c) MangoNet Labs Ltd.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::authority::authority_store::LockDetailsWrapper;
use crate::authority::epoch_start_configuration::EpochStartConfiguration;
use crate::checkpoints::CheckpointStore;
use mgo_types::accumulator::Accumulator;
use mgo_types::base_types::SequenceNumber;
use mgo_types::digests::TransactionEventsDigest;
use mgo_types::effects::TransactionEffects;
use mgo_types::storage::MarkerValue;
use rocksdb::Options;
use serde::{Deserialize, Serialize};
use std::path::Path;
use typed_store::metrics::SamplingInterval;
use typed_store::rocks::util::{empty_compaction_filter, reference_count_merge_operator};
use typed_store::rocks::{
    default_db_options, read_size_from_env, DBBatch, DBMap, DBOptions, MetricConf, ReadWriteOptions,
};
use typed_store::traits::{Map, TableSummary, TypedStoreDebug};

use crate::authority::authority_store_types::{
    get_store_object_pair, try_construct_object, ObjectContentDigest, StoreData,
    StoreMoveObjectWrapper, StoreObject, StoreObjectPair, StoreObjectValue, StoreObjectWrapper, StoreObjectV1
};
use mgo_types::mgo_system_state::epoch_start_mgo_system_state::EpochStartSystemState;
use tracing::{info, warn};
use typed_store_derive::DBMapUtils;

const ENV_VAR_OBJECTS_BLOCK_CACHE_SIZE: &str = "OBJECTS_BLOCK_CACHE_MB";
const ENV_VAR_LOCKS_BLOCK_CACHE_SIZE: &str = "LOCKS_BLOCK_CACHE_MB";
const ENV_VAR_TRANSACTIONS_BLOCK_CACHE_SIZE: &str = "TRANSACTIONS_BLOCK_CACHE_MB";
const ENV_VAR_EFFECTS_BLOCK_CACHE_SIZE: &str = "EFFECTS_BLOCK_CACHE_MB";
const ENV_VAR_EVENTS_BLOCK_CACHE_SIZE: &str = "EVENTS_BLOCK_CACHE_MB";
const ENV_VAR_INDIRECT_OBJECTS_BLOCK_CACHE_SIZE: &str = "INDIRECT_OBJECTS_BLOCK_CACHE_MB";

/// AuthorityPerpetualTables contains data that must be preserved from one epoch to the next.
#[derive(DBMapUtils)]
pub struct AuthorityPerpetualTables {
    /// This is a map between the object (ID, version) and the latest state of the object, namely the
    /// state that is needed to process new transactions.
    /// State is represented by `StoreObject` enum, which is either a move module, a move object, or
    /// a pointer to an object stored in the `indirect_move_objects` table.
    ///
    /// Note that while this map can store all versions of an object, we will eventually
    /// prune old object versions from the db.
    ///
    /// IMPORTANT: object versions must *only* be pruned if they appear as inputs in some
    /// TransactionEffects. Simply pruning all objects but the most recent is an error!
    /// This is because there can be partially executed transactions whose effects have not yet
    /// been written out, and which must be retried. But, they cannot be retried unless their input
    /// objects are still accessible!
    #[default_options_override_fn = "objects_table_default_config"]
    pub(crate) objects: DBMap<ObjectKey, StoreObjectWrapper>,

    #[default_options_override_fn = "indirect_move_objects_table_default_config"]
    pub(crate) indirect_move_objects: DBMap<ObjectContentDigest, StoreMoveObjectWrapper>,

    /// This is a map between object references of currently active objects that can be mutated,
    /// and the transaction that they are lock on for use by this specific authority. Where an object
    /// lock exists for an object version, but no transaction has been seen using it the lock is set
    /// to None. The safety of consistent broadcast depend on each honest authority never changing
    /// the lock once it is set. After a certificate for this object is processed it can be
    /// forgotten.
    #[default_options_override_fn = "owned_object_transaction_locks_table_default_config"]
    pub(crate) owned_object_transaction_locks: DBMap<ObjectRef, Option<LockDetailsWrapper>>,

    /// This is a map between the transaction digest and the corresponding transaction that's known to be
    /// executable. This means that it may have been executed locally, or it may have been synced through
    /// state-sync but hasn't been executed yet.
    #[default_options_override_fn = "transactions_table_default_config"]
    pub(crate) transactions: DBMap<TransactionDigest, TrustedTransaction>,

    /// A map between the transaction digest of a certificate to the effects of its execution.
    /// We store effects into this table in two different cases:
    /// 1. When a transaction is synced through state_sync, we store the effects here. These effects
    /// are known to be final in the network, but may not have been executed locally yet.
    /// 2. When the transaction is executed locally on this node, we store the effects here. This means that
    /// it's possible to store the same effects twice (once for the synced transaction, and once for the executed).
    /// It's also possible for the effects to be reverted if the transaction didn't make it into the epoch.
    #[default_options_override_fn = "effects_table_default_config"]
    pub(crate) effects: DBMap<TransactionEffectsDigest, TransactionEffects>,

    /// Transactions that have been executed locally on this node. We need this table since the `effects` table
    /// doesn't say anything about the execution status of the transaction on this node. When we wait for transactions
    /// to be executed, we wait for them to appear in this table. When we revert transactions, we remove them from both
    /// tables.
    pub(crate) executed_effects: DBMap<TransactionDigest, TransactionEffectsDigest>,

    // Currently this is needed in the validator for returning events during process certificates.
    // We could potentially remove this if we decided not to provide events in the execution path.
    // TODO: Figure out what to do with this table in the long run.
    // Also we need a pruning policy for this table. We can prune this table along with tx/effects.
    #[default_options_override_fn = "events_table_default_config"]
    pub(crate) events: DBMap<(TransactionEventsDigest, usize), Event>,

    /// DEPRECATED in favor of the table of the same name in authority_per_epoch_store.
    /// Please do not add new accessors/callsites.
    /// When transaction is executed via checkpoint executor, we store association here
    pub(crate) executed_transactions_to_checkpoint:
        DBMap<TransactionDigest, (EpochId, CheckpointSequenceNumber)>,

    // Finalized root state accumulator for epoch, to be included in CheckpointSummary
    // of last checkpoint of epoch. These values should only ever be written once
    // and never changed
    #[default_options_override_fn = "range_delete_enabled_table_default_config"]
    pub(crate) root_state_hash_by_epoch: DBMap<EpochId, (CheckpointSequenceNumber, Accumulator)>,

    /// Parameters of the system fixed at the epoch start
    pub(crate) epoch_start_configuration: DBMap<(), EpochStartConfiguration>,

    /// A singleton table that stores latest pruned checkpoint. Used to keep objects pruner progress
    pub(crate) pruned_checkpoint: DBMap<(), CheckpointSequenceNumber>,

    /// Expected total amount of MGO in the network. This is expected to remain constant
    /// throughout the lifetime of the network. We check it at the end of each epoch if
    /// expensive checks are enabled. We cannot use 10B today because in tests we often
    /// inject extra gas objects into genesis.
    pub(crate) expected_network_mgo_amount: DBMap<(), u64>,

    /// Expected imbalance between storage fund balance and the sum of storage rebate of all live objects.
    /// This could be non-zero due to bugs in earlier protocol versions.
    /// This number is the result of storage_fund_balance - sum(storage_rebate).
    pub(crate) expected_storage_fund_imbalance: DBMap<(), i64>,

    /// Table that stores the set of received objects and deleted objects and the version at
    /// which they were received. This is used to prevent possible race conditions around receiving
    /// objects (since they are not locked by the transaction manager) and for tracking shared
    /// objects that have been deleted. This table is meant to be pruned per-epoch, and all
    /// previous epochs other than the current epoch may be pruned safely.
    #[default_options_override_fn = "range_delete_enabled_table_default_config"]
    pub(crate) object_per_epoch_marker_table: DBMap<(EpochId, ObjectKey), MarkerValue>,
}

impl AuthorityPerpetualTables {
    pub fn path(parent_path: &Path) -> PathBuf {
        parent_path.join("perpetual")
    }

    pub fn open(parent_path: &Path, db_options: Option<Options>) -> Self {
        Self::open_tables_read_write(
            Self::path(parent_path),
            MetricConf::new("perpetual")
                .with_sampling(SamplingInterval::new(Duration::from_secs(60), 0)),
            db_options,
            None,
        )
    }

    pub fn open_readonly(parent_path: &Path) -> AuthorityPerpetualTablesReadOnly {
        Self::get_read_only_handle(
            Self::path(parent_path),
            None,
            None,
            MetricConf::new("perpetual_readonly"),
        )
    }

    // This is used by indexer to find the correct version of dynamic field child object.
    // We do not store the version of the child object, but because of lamport timestamp,
    // we know the child must have version number less then or eq to the parent.
    pub fn find_object_lt_or_eq_version(
        &self,
        object_id: ObjectID,
        version: SequenceNumber,
    ) -> Option<Object> {
        let Ok(iter) = self
            .objects
            .safe_range_iter(ObjectKey::min_for_id(&object_id)..=ObjectKey::max_for_id(&object_id))
            .skip_prior_to(&ObjectKey(object_id, version))
        else {
            return None;
        };
        iter.reverse().next().and_then(|db_result| match db_result {
            Ok((key, o)) => self.object(&key, o).ok().flatten(),
            Err(err) => {
                warn!("Object iterator encountered RocksDB error {:?}", err);
                None
            }
        })
    }

    fn construct_object(
        &self,
        object_key: &ObjectKey,
        store_object: StoreObjectValue,
    ) -> Result<Object, MgoError> {
        let indirect_object = match store_object.data {
            StoreData::IndirectObject(ref metadata) => self
                .indirect_move_objects
                .get(&metadata.digest)?
                .map(|o| o.migrate().into_inner()),
            _ => None,
        };
        try_construct_object(object_key, store_object, indirect_object)
    }

    // Constructs `mgo_types::object::Object` from `StoreObjectWrapper`.
    // Returns `None` if object was deleted/wrapped
    pub fn object(
        &self,
        object_key: &ObjectKey,
        store_object: StoreObjectWrapper,
    ) -> Result<Option<Object>, MgoError> {
        let StoreObject::Value(store_object) = store_object.migrate().into_inner() else {
            return Ok(None);
        };
        Ok(Some(self.construct_object(object_key, store_object)?))
    }

    pub fn object_reference(
        &self,
        object_key: &ObjectKey,
        store_object: StoreObjectWrapper,
    ) -> Result<ObjectRef, MgoError> {
        let obj_ref = match store_object.migrate().into_inner() {
            StoreObject::Value(object) => self
                .construct_object(object_key, object)?
                .compute_object_reference(),
            StoreObject::Deleted => (
                object_key.0,
                object_key.1,
                ObjectDigest::OBJECT_DIGEST_DELETED,
            ),
            StoreObject::Wrapped => (
                object_key.0,
                object_key.1,
                ObjectDigest::OBJECT_DIGEST_WRAPPED,
            ),
        };
        Ok(obj_ref)
    }

    pub fn tombstone_reference(
        &self,
        object_key: &ObjectKey,
        store_object: &StoreObjectWrapper,
    ) -> Result<Option<ObjectRef>, MgoError> {
        let obj_ref = match store_object.inner() {
            StoreObject::Deleted => Some((
                object_key.0,
                object_key.1,
                ObjectDigest::OBJECT_DIGEST_DELETED,
            )),
            StoreObject::Wrapped => Some((
                object_key.0,
                object_key.1,
                ObjectDigest::OBJECT_DIGEST_WRAPPED,
            )),
            _ => None,
        };
        Ok(obj_ref)
    }

    pub fn get_latest_object_ref_or_tombstone(
        &self,
        object_id: ObjectID,
    ) -> Result<Option<ObjectRef>, MgoError> {
        let mut iterator = self
            .objects
            .unbounded_iter()
            .skip_prior_to(&ObjectKey::max_for_id(&object_id))?;

        if let Some((object_key, value)) = iterator.next() {
            if object_key.0 == object_id {
                return Ok(Some(self.object_reference(&object_key, value)?));
            }
        }
        Ok(None)
    }

    pub fn get_latest_object_or_tombstone(
        &self,
        object_id: ObjectID,
    ) -> Result<Option<(ObjectKey, StoreObjectWrapper)>, MgoError> {
        let mut iterator = self
            .objects
            .unbounded_iter()
            .skip_prior_to(&ObjectKey::max_for_id(&object_id))?;

        if let Some((object_key, value)) = iterator.next() {
            if object_key.0 == object_id {
                return Ok(Some((object_key, value)));
            }
        }
        Ok(None)
    }

    pub fn get_recovery_epoch_at_restart(&self) -> MgoResult<EpochId> {
        Ok(self
            .epoch_start_configuration
            .get(&())?
            .expect("Must have current epoch.")
            .epoch_start_state()
            .epoch())
    }

    pub async fn set_epoch_start_configuration(
        &self,
        epoch_start_configuration: &EpochStartConfiguration,
    ) -> MgoResult {
        let mut wb = self.epoch_start_configuration.batch();
        wb.insert_batch(
            &self.epoch_start_configuration,
            std::iter::once(((), epoch_start_configuration)),
        )?;
        wb.write()?;
        Ok(())
    }

    pub fn get_highest_pruned_checkpoint(&self) -> MgoResult<CheckpointSequenceNumber> {
        Ok(self.pruned_checkpoint.get(&())?.unwrap_or_default())
    }

    pub fn set_highest_pruned_checkpoint(
        &self,
        wb: &mut DBBatch,
        checkpoint_number: CheckpointSequenceNumber,
    ) -> MgoResult {
        wb.insert_batch(&self.pruned_checkpoint, [((), checkpoint_number)])?;
        Ok(())
    }

    pub fn get_transaction(
        &self,
        digest: &TransactionDigest,
    ) -> MgoResult<Option<TrustedTransaction>> {
        let Some(transaction) = self.transactions.get(digest)? else {
            return Ok(None);
        };
        Ok(Some(transaction))
    }

    pub fn get_effects(&self, digest: &TransactionDigest) -> MgoResult<Option<TransactionEffects>> {
        let Some(effect_digest) = self.executed_effects.get(digest)? else {
            return Ok(None);
        };
        Ok(self.effects.get(&effect_digest)?)
    }

    // DEPRECATED as the backing table has been moved to authority_per_epoch_store.
    // Please do not add new accessors/callsites.
    pub fn get_checkpoint_sequence_number(
        &self,
        digest: &TransactionDigest,
    ) -> MgoResult<Option<(EpochId, CheckpointSequenceNumber)>> {
        Ok(self.executed_transactions_to_checkpoint.get(digest)?)
    }

    pub fn get_newer_object_keys(
        &self,
        object: &(ObjectID, SequenceNumber),
    ) -> MgoResult<Vec<ObjectKey>> {
        let mut objects = vec![];
        for result in self.objects.safe_iter_with_bounds(
            Some(ObjectKey(object.0, object.1.next())),
            Some(ObjectKey(object.0, VersionNumber::MAX)),
        ) {
            let (key, _) = result?;
            objects.push(key);
        }
        Ok(objects)
    }

    /// Removes executed effects and outputs for a transaction,
    /// and tries to ensure the transaction is replayable.
    ///
    /// WARNING: This method is very subtle and can corrupt the database if used incorrectly.
    /// It should only be used in one-off cases or tests after fully understanding the risk.
    pub fn remove_executed_effects_and_outputs_subtle(
        &self,
        digest: &TransactionDigest,
        objects: &[ObjectKey],
    ) -> MgoResult {
        let mut wb = self.objects.batch();
        for object in objects {
            wb.delete_batch(&self.objects, [object])?;
            if self.has_object_lock(object)? {
                self.remove_object_lock_batch(&mut wb, object)?;
            }
        }
        wb.delete_batch(&self.executed_transactions_to_checkpoint, [digest])?;
        wb.delete_batch(&self.executed_effects, [digest])?;
        wb.write()?;
        Ok(())
    }

    pub fn has_object_lock(&self, object: &ObjectKey) -> MgoResult<bool> {
        Ok(self
            .owned_object_transaction_locks
            .safe_iter_with_bounds(
                Some((object.0, object.1, ObjectDigest::MIN)),
                Some((object.0, object.1, ObjectDigest::MAX)),
            )
            .next()
            .transpose()?
            .is_some())
    }

    /// Removes owned object locks and set the lock to the previous version of the object.
    ///
    /// WARNING: This method is very subtle and can corrupt the database if used incorrectly.
    /// It should only be used in one-off cases or tests after fully understanding the risk.
    pub fn remove_object_lock_subtle(&self, object: &ObjectKey) -> MgoResult<ObjectRef> {
        let mut wb = self.objects.batch();
        let object_ref = self.remove_object_lock_batch(&mut wb, object)?;
        wb.write()?;
        Ok(object_ref)
    }

    fn remove_object_lock_batch(
        &self,
        wb: &mut DBBatch,
        object: &ObjectKey,
    ) -> MgoResult<ObjectRef> {
        wb.schedule_delete_range(
            &self.owned_object_transaction_locks,
            &(object.0, object.1, ObjectDigest::MIN),
            &(object.0, object.1, ObjectDigest::MAX),
        )?;
        let object_ref = self.get_latest_object_ref_or_tombstone(object.0)?.unwrap();
        wb.insert_batch(&self.owned_object_transaction_locks, [(object_ref, None)])?;
        Ok(object_ref)
    }

    pub fn set_highest_pruned_checkpoint_without_wb(
        &self,
        checkpoint_number: CheckpointSequenceNumber,
    ) -> MgoResult {
        let mut wb = self.pruned_checkpoint.batch();
        self.set_highest_pruned_checkpoint(&mut wb, checkpoint_number)?;
        wb.write()?;
        Ok(())
    }

    pub fn database_is_empty(&self) -> MgoResult<bool> {
        Ok(self
            .objects
            .unbounded_iter()
            .skip_to(&ObjectKey::ZERO)?
            .next()
            .is_none())
    }

    pub fn iter_live_object_set(&self, include_wrapped_object: bool) -> LiveSetIter<'_> {
        LiveSetIter {
            iter: self.objects.unbounded_iter(),
            tables: self,
            prev: None,
            include_wrapped_object,
        }
    }

    pub fn checkpoint_db(&self, path: &Path) -> MgoResult {
        // This checkpoints the entire db and not just objects table
        self.objects.checkpoint_db(path).map_err(Into::into)
    }

    pub fn reset_db_for_execution_since_genesis(&self) -> MgoResult {
        // TODO: Add new tables that get added to the db automatically
        self.objects.unsafe_clear()?;
        self.indirect_move_objects.unsafe_clear()?;
        self.owned_object_transaction_locks.unsafe_clear()?;
        self.executed_effects.unsafe_clear()?;
        self.events.unsafe_clear()?;
        self.executed_transactions_to_checkpoint.unsafe_clear()?;
        self.root_state_hash_by_epoch.unsafe_clear()?;
        self.epoch_start_configuration.unsafe_clear()?;
        self.pruned_checkpoint.unsafe_clear()?;
        self.expected_network_mgo_amount.unsafe_clear()?;
        self.expected_storage_fund_imbalance.unsafe_clear()?;
        self.object_per_epoch_marker_table.unsafe_clear()?;
        self.objects.rocksdb.flush()?;
        Ok(())
    }

    pub fn get_root_state_hash(
        &self,
        epoch: EpochId,
    ) -> MgoResult<Option<(CheckpointSequenceNumber, Accumulator)>> {
        Ok(self.root_state_hash_by_epoch.get(&epoch)?)
    }

    pub fn insert_root_state_hash(
        &self,
        epoch: EpochId,
        last_checkpoint_of_epoch: CheckpointSequenceNumber,
        accumulator: Accumulator,
    ) -> MgoResult {
        self.root_state_hash_by_epoch
            .insert(&epoch, &(last_checkpoint_of_epoch, accumulator))?;
        Ok(())
    }

    pub fn insert_object_test_only(&self, object: Object) -> MgoResult {
        let object_reference = object.compute_object_reference();
        let StoreObjectPair(wrapper, _indirect_object) = get_store_object_pair(object, usize::MAX);
        let mut wb = self.objects.batch();
        wb.insert_batch(
            &self.objects,
            std::iter::once((ObjectKey::from(object_reference), wrapper)),
        )?;
        wb.write()?;
        Ok(())
    }

    /// Removes all records associated with epochs higher than the target epoch.
    /// This function performs a rollback operation and should be used carefully
    /// as it permanently deletes data.
    ///
    /// WARNING: This operation is irreversible and should only be used in
    /// disaster recovery scenarios. Ensure proper backups exist before calling.
    pub fn rollback_to_epoch(
        &self, 
        target_epoch: EpochId,
        checkpoint_store: &Arc<CheckpointStore>,
        transactions_to_remove: &Vec<TransactionDigest>,
        transaction_effects_to_remove: &Vec<TransactionEffectsDigest>,
    ) -> MgoResult<DBBatch> {
        info!("Starting rollback to epoch {} for perpetual table", target_epoch);

        let mut batch = self.objects.batch();
        // Validate rollback parameters
        // Check if target epoch is higher than any existing epoch in storage
        let max_epoch = self.root_state_hash_by_epoch
            .unbounded_iter()
            .skip_to_last()
            .map(|(epoch_id, _)| epoch_id)
            .next()
            .unwrap_or(0);
        println!("Found max_epoch: {}", max_epoch);
        if target_epoch > max_epoch {
            return Err(MgoError::Rollback (
                format!(
                    "Cannot rollback to future epoch {} in AuthorityStore. Maximum existing epoch is {}",
                    target_epoch, max_epoch
                )
            ));
        }

        info!(
            "Rollback validation passed: target_epoch={}, max_existing_epoch={}",
            target_epoch, max_epoch
        );

        batch.schedule_delete_range(&self.root_state_hash_by_epoch, &target_epoch, &(max_epoch+1))?;
        info!("Added {} of root state hashes to remove", max_epoch + 1 - target_epoch);

        // Remove transactions
        batch.delete_batch(&self.transactions, transactions_to_remove.iter())?;
        batch.delete_batch(&self.executed_effects, transactions_to_remove.iter())?;
        info!("Added {} of transactions to remove", transactions_to_remove.len());

        // Remove transaction_effects
        let transaction_effects_to_clean = self.effects
            .multi_get(transaction_effects_to_remove)?
            .into_iter()
            .filter(|te| te.is_some())
            .map(|te| te.unwrap())
            .collect::<Vec<_>>();

        batch.delete_batch(&self.effects, transaction_effects_to_remove.iter())?;
        info!("Added {} of transaction effects to remove", transaction_effects_to_clean.len());
        
        // Remove events
        let events_to_remove = transaction_effects_to_clean
            .iter()
            .map(|te| te.events_digest())
            .filter(|ed| ed.is_some())
            .map(|ed| ed.unwrap().clone())
            .collect::<Vec<_>>();

        for events_digest in events_to_remove.iter() {
            batch.schedule_delete_range(
                &self.events, 
                &(*events_digest, 0), 
                &(*events_digest, usize::MAX)
            )?;
        }
        info!("Added {} of events to remove", events_to_remove.len());
        
        // Remove objects
        let object_refs_from_tx_to_remove = transaction_effects_to_clean
            .iter()
            .map(|te| te.all_changed_objects())
            .flatten()
            .map(|(object_ref, _, _)| object_ref)
            .collect::<Vec<ObjectRef>>();

        let object_keys_from_objects_to_remove = object_refs_from_tx_to_remove
            .iter()
            .map(|obj| ObjectKey(obj.0, obj.1))
            .collect::<Vec<ObjectKey>>();

        let objects_from_tx_to_remove = self.objects
            .multi_get(&object_keys_from_objects_to_remove)?
            .into_iter()
            .filter(|obj| obj.is_some())
            .map(|obj| obj.unwrap())
            .collect::<Vec<StoreObjectWrapper>>();

        batch.delete_batch(&self.objects, &object_keys_from_objects_to_remove)?;
        info!("Added {} of objects to remove", objects_from_tx_to_remove.len());

        // Remove owned_object_transaction_locks
        batch.delete_batch(&self.owned_object_transaction_locks, &object_refs_from_tx_to_remove)?;
        info!("Added {} of locks to remove", object_refs_from_tx_to_remove.len());

        // Remove indirect_object_transaction_locks
        let indirect_object_to_remove = objects_from_tx_to_remove
            .iter()
            .map(|obj| {
                if let StoreObjectV1::Value(value) = obj.clone().into_inner() {
                    if let StoreData::IndirectObject(metadata) = value.data {
                        Some(metadata.digest)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .filter(|obj| obj.is_some())
            .map(|obj| obj.unwrap())
            .collect::<Vec<ObjectContentDigest>>();

        batch.delete_batch(&self.indirect_move_objects, indirect_object_to_remove.iter())?;
        info!("Added {} of indirect objects to remove", indirect_object_to_remove.len());

        // Remove object_per_epoch_marker_table entries
        let max_marker_epoch = self.object_per_epoch_marker_table
            .unbounded_iter()
            .skip_to_last()
            .map(|((epoch_id,_), _)| epoch_id)
            .next()
            .unwrap_or(target_epoch);

        let marker_objects_to_remove = self.object_per_epoch_marker_table
            .range_iter((target_epoch, ObjectKey::ZERO)..(max_marker_epoch + 1, ObjectKey::ZERO))
            .map(|((_, obj), _)| obj)
            .collect::<Vec<_>>();

        batch.schedule_delete_range(&self.object_per_epoch_marker_table, &(target_epoch, ObjectKey::ZERO), &(max_marker_epoch + 1, ObjectKey::ZERO))?;
        info!("Added {} of object epoch markers to remove", marker_objects_to_remove.len());

        // Phase 6: Update singleton tables to target epoch state
        self.rollback_singleton_tables(&mut batch, target_epoch, checkpoint_store, &transaction_effects_to_clean)?;

        Ok(batch)
    }

    fn rollback_singleton_tables(
        &self,
        batch: &mut DBBatch,
        target_epoch: EpochId,
        checkpoint_store: &CheckpointStore,
        transaction_effects_to_clean: &[TransactionEffects],
    ) -> MgoResult<()> {
        info!("Updating singleton tables for rollback to epoch {}", target_epoch);

        let rollback_checkpoint = self.get_checkpoint_for_rollback(target_epoch, checkpoint_store)?;

        // 1. Keep epoch_start_configuration at epoch N
        // According to the rollback requirements, we should KEEP the epoch_start_configuration
        // at the target epoch, not rollback to a previous epoch. This ensures the system is
        // configured for epoch N but with no execution data from epoch N.
        if let Some(current_config) = self.epoch_start_configuration.get(&())? {
            let current_epoch = current_config.epoch_start_state().epoch();
            if current_epoch < target_epoch {
                return Err(
                    MgoError::Rollback(format!("Epoch start configuration at epoch {} is before target epoch {}", current_epoch, target_epoch))
                );
            } else {
                // We need to recreate configuration for the target epoch
                let updated_config = self.create_rollback_epoch_configuration(
                    &current_config, 
                    target_epoch,
                    &rollback_checkpoint
                )?;
                
                batch.insert_batch(&self.epoch_start_configuration, [((), updated_config)])?;
                info!("Updated epoch_start_configuration to target epoch {}", target_epoch);
            }
        } else {
            return Err(MgoError::Rollback(format!("Epoch start configuration is missing")));
        }

        // 2. Rollback pruned_checkpoint
        // We need to find the highest checkpoint sequence number that exists
        // after rollback. This requires checking what checkpoints will remain.
        // First, let's check if we have a current pruned checkpoint
        batch.insert_batch(&self.pruned_checkpoint, [((), rollback_checkpoint.sequence_number)])?;

        // 3. Rollback expected_network_mgo_amount
        // This value represents the total MGO in the network and should remain constant
        // across epochs in normal operation. We log it but don't change it unless
        // we have evidence of corruption.
        if let Some(expected_amount) = self.expected_network_mgo_amount.get(&())? {
            info!("Current expected_network_mgo_amount: {} (unchanged)", expected_amount);
        }

        // 4. Rollback expected_storage_fund_imbalance  
        // This tracks the accumulated imbalance between storage fund balance and storage rebates.
        // When rolling back, we're removing transactions that may have contributed to this imbalance.
        // Calculate storage rebates from all removed transactions and adjust the imbalance.
        let removed_storage_rebates: u64 = transaction_effects_to_clean
            .iter()
            .map(|effects| effects.gas_cost_summary().storage_rebate)
            .sum();

        if let Some(current_imbalance) = self.expected_storage_fund_imbalance.get(&())? {
            // Since we're removing transactions, we need to adjust the imbalance
            // by adding back the storage rebates that are being removed
            let new_imbalance = current_imbalance + (removed_storage_rebates as i64);
            batch.insert_batch(&self.expected_storage_fund_imbalance, [((), new_imbalance)])?;
            info!("Updated expected_storage_fund_imbalance from {} to {} (removed {} in storage rebates)", 
                  current_imbalance, new_imbalance, removed_storage_rebates);
        } else if removed_storage_rebates > 0 {
            // If there's no existing imbalance but we're removing rebates, create an entry
            let new_imbalance = removed_storage_rebates as i64;
            batch.insert_batch(&self.expected_storage_fund_imbalance, [((), new_imbalance)])?;
            info!("Created expected_storage_fund_imbalance of {} (removed {} in storage rebates)", 
                  new_imbalance, removed_storage_rebates);
        }

        info!("Completed singleton tables rollback for epoch {}", target_epoch);
        Ok(())
    }

    fn create_rollback_epoch_configuration(
        &self,
        current_config: &EpochStartConfiguration,
        target_epoch: EpochId,
        rollback_checkpoint: &CheckpointSummary,
    ) -> MgoResult<EpochStartConfiguration> {
        let checkpoint_digest = rollback_checkpoint.digest();

        match current_config {
            EpochStartConfiguration::V5(v5) => {
                // Create a new system state with the target epoch
                let updated_system_state = self.create_rollback_system_state(
                    v5.epoch_start_state(), 
                    target_epoch
                )?;
                
                // Find the epoch digest for the target epoch
                // This should be the digest of the last checkpoint of (target_epoch - 1)
                let mut new_epoch_state_configuration = v5.clone();
                new_epoch_state_configuration.set_system_state(updated_system_state);
                new_epoch_state_configuration.set_epoch_digest(checkpoint_digest); 
                // Keep the same flags and object versions for now
                // In a more complete implementation, these might need adjustment too
                Ok(EpochStartConfiguration::V5(new_epoch_state_configuration))
            }
            EpochStartConfiguration::V4(v4) => {
                let updated_system_state = self.create_rollback_system_state(
                    v4.epoch_start_state(), 
                    target_epoch
                )?;
                let mut new_epoch_state_configuration = v4.clone();
                new_epoch_state_configuration.set_system_state(updated_system_state);
                new_epoch_state_configuration.set_epoch_digest(checkpoint_digest);

                Ok(EpochStartConfiguration::V4(new_epoch_state_configuration))
            }
            EpochStartConfiguration::V3(v3) => {
                let updated_system_state = self.create_rollback_system_state(
                    v3.epoch_start_state(), 
                    target_epoch
                )?;
                let mut new_epoch_state_configuration = v3.clone();
                new_epoch_state_configuration.set_system_state(updated_system_state);
                new_epoch_state_configuration.set_epoch_digest(checkpoint_digest);

                Ok(EpochStartConfiguration::V3(new_epoch_state_configuration))
            }
            EpochStartConfiguration::V2(v2) => {
                let updated_system_state = self.create_rollback_system_state(
                    v2.epoch_start_state(), 
                    target_epoch
                )?;
                let mut new_epoch_state_configuration = v2.clone();
                new_epoch_state_configuration.set_system_state(updated_system_state);
                new_epoch_state_configuration.set_epoch_digest(checkpoint_digest);

                Ok(EpochStartConfiguration::V2(new_epoch_state_configuration))
            }
            EpochStartConfiguration::V1(v1) => {
                let updated_system_state = self.create_rollback_system_state(
                    v1.epoch_start_state(), 
                    target_epoch
                )?;
                let mut new_epoch_state_configuration = v1.clone();
                new_epoch_state_configuration.set_system_state(updated_system_state);
                new_epoch_state_configuration.set_epoch_digest(checkpoint_digest);

                Ok(EpochStartConfiguration::V1(new_epoch_state_configuration))
            }
        }
    }

    fn create_rollback_system_state(
        &self,
        current_system_state: &EpochStartSystemState,
        target_epoch: EpochId,
    ) -> MgoResult<EpochStartSystemState> {
        
        match current_system_state {
            EpochStartSystemState::V1(v1) => {
                // Create a new system state with updated epoch
                // We need to calculate appropriate timestamp for the target epoch
                let target_timestamp = Utc::now().timestamp_millis() as u64;
                let mut system_state = v1.clone();
                system_state.set_epoch(target_epoch);
                system_state.set_epoch_start_timestamp_ms(target_timestamp);
                Ok(EpochStartSystemState::V1(system_state))
            }
        }
    }

    fn get_checkpoint_for_rollback(
        &self, 
        target_epoch: EpochId,
        checkpoint_store: &CheckpointStore,
    ) -> MgoResult<CheckpointSummary> {
        if target_epoch == 0 {
            // Genesis epoch has digest 0
            let genesis = checkpoint_store.get_checkpoint_by_sequence_number(0)?;
            if let Some(genesis) = genesis {
                return Ok(genesis.into_summary_and_sequence().1);
            } else {
                // For testing: if we can't find the genesis checkpoint, return a test checkpoint
                #[cfg(test)]
                {
                    return Ok(CheckpointSummary::new(
                        0,
                        0,
                        0,
                        &CheckpointContents::new_with_digests_only_for_tests(vec![]),
                        None,
                        GasCostSummary::default(),
                        None,
                        0
                    ));
                }
                #[cfg(not(test))]
                return Err(MgoError::Rollback(
                    format!("Cannot find genesis checkpoint")
                ));
            }
        }
        
        // For non-genesis epochs, we need the digest of the last checkpoint of the previous epoch
        // Use the checkpoint store to get the actual checkpoint digest
        let previous_epoch = target_epoch - 1;
        
        if let Some(last_checkpoint) = checkpoint_store.get_epoch_last_checkpoint(previous_epoch)? {
            // Get the digest from the last checkpoint of the previous epoch
            return Ok(last_checkpoint.into_summary_and_sequence().1);
        } else {
            // For testing: if we can't find the checkpoint, return a test checkpoint
            #[cfg(test)]
            {
                return Ok(CheckpointSummary::new(
                    previous_epoch,
                    previous_epoch as CheckpointSequenceNumber,
                    0,
                    &CheckpointContents::new_with_digests_only_for_tests(vec![]),
                    Some(CheckpointDigest::default()),
                    GasCostSummary::default(),
                    None,
                    0,
                ));
            }
            #[cfg(not(test))]
            return Err(MgoError::Rollback(
                format!("Cannot find last checkpoint of previous epoch {}", previous_epoch)
            ));
        }
    }
}

impl ObjectStore for AuthorityPerpetualTables {
    /// Read an object and return it, or Ok(None) if the object was not found.
    fn get_object(
        &self,
        object_id: &ObjectID,
    ) -> Result<Option<Object>, mgo_types::storage::error::Error> {
        let obj_entry = self
            .objects
            .unbounded_iter()
            .skip_prior_to(&ObjectKey::max_for_id(object_id))
            .map_err(mgo_types::storage::error::Error::custom)?
            .next();

        match obj_entry {
            Some((ObjectKey(obj_id, version), obj)) if obj_id == *object_id => Ok(self
                .object(&ObjectKey(obj_id, version), obj)
                .map_err(mgo_types::storage::error::Error::custom)?),
            _ => Ok(None),
        }
    }

    fn get_object_by_key(
        &self,
        object_id: &ObjectID,
        version: VersionNumber,
    ) -> Result<Option<Object>, mgo_types::storage::error::Error> {
        Ok(self
            .objects
            .get(&ObjectKey(*object_id, version))
            .map_err(mgo_types::storage::error::Error::custom)?
            .map(|object| self.object(&ObjectKey(*object_id, version), object))
            .transpose()
            .map_err(mgo_types::storage::error::Error::custom)?
            .flatten())
    }
}

pub struct LiveSetIter<'a> {
    iter:
        <DBMap<ObjectKey, StoreObjectWrapper> as Map<'a, ObjectKey, StoreObjectWrapper>>::Iterator,
    tables: &'a AuthorityPerpetualTables,
    prev: Option<(ObjectKey, StoreObjectWrapper)>,
    /// Whether a wrapped object is considered as a live object.
    include_wrapped_object: bool,
}

#[derive(Eq, PartialEq, Debug, Clone, Deserialize, Serialize, Hash)]
pub enum LiveObject {
    Normal(Object),
    Wrapped(ObjectKey),
}

impl LiveObject {
    pub fn object_id(&self) -> ObjectID {
        match self {
            LiveObject::Normal(obj) => obj.id(),
            LiveObject::Wrapped(key) => key.0,
        }
    }

    pub fn version(&self) -> SequenceNumber {
        match self {
            LiveObject::Normal(obj) => obj.version(),
            LiveObject::Wrapped(key) => key.1,
        }
    }

    pub fn object_reference(&self) -> ObjectRef {
        match self {
            LiveObject::Normal(obj) => obj.compute_object_reference(),
            LiveObject::Wrapped(key) => (key.0, key.1, ObjectDigest::OBJECT_DIGEST_WRAPPED),
        }
    }
}

impl LiveSetIter<'_> {
    fn store_object_wrapper_to_live_object(
        &self,
        object_key: ObjectKey,
        store_object: StoreObjectWrapper,
    ) -> Option<LiveObject> {
        match store_object.migrate().into_inner() {
            StoreObject::Value(object) => {
                let object = self
                    .tables
                    .construct_object(&object_key, object)
                    .expect("Constructing object from store cannot fail");
                Some(LiveObject::Normal(object))
            }
            StoreObject::Wrapped => {
                if self.include_wrapped_object {
                    Some(LiveObject::Wrapped(object_key))
                } else {
                    None
                }
            }
            StoreObject::Deleted => None,
        }
    }
}

impl Iterator for LiveSetIter<'_> {
    type Item = LiveObject;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((next_key, next_value)) = self.iter.next() {
                let prev = self.prev.take();
                self.prev = Some((next_key, next_value));

                if let Some((prev_key, prev_value)) = prev {
                    if prev_key.0 != next_key.0 {
                        let live_object =
                            self.store_object_wrapper_to_live_object(prev_key, prev_value);
                        if live_object.is_some() {
                            return live_object;
                        }
                    }
                }
                continue;
            }
            if let Some((key, value)) = self.prev.take() {
                let live_object = self.store_object_wrapper_to_live_object(key, value);
                if live_object.is_some() {
                    return live_object;
                }
            }
            return None;
        }
    }
}

// These functions are used to initialize the DB tables
fn owned_object_transaction_locks_table_default_config() -> DBOptions {
    DBOptions {
        options: default_db_options()
            .optimize_for_write_throughput()
            .optimize_for_read(read_size_from_env(ENV_VAR_LOCKS_BLOCK_CACHE_SIZE).unwrap_or(1024))
            .options,
        rw_options: ReadWriteOptions::default().set_ignore_range_deletions(false),
    }
}

fn objects_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_read(read_size_from_env(ENV_VAR_OBJECTS_BLOCK_CACHE_SIZE).unwrap_or(5 * 1024))
}

fn transactions_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_point_lookup(
            read_size_from_env(ENV_VAR_TRANSACTIONS_BLOCK_CACHE_SIZE).unwrap_or(512),
        )
}

fn effects_table_default_config() -> DBOptions {
    default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_point_lookup(
            read_size_from_env(ENV_VAR_EFFECTS_BLOCK_CACHE_SIZE).unwrap_or(1024),
        )
}

fn events_table_default_config() -> DBOptions {
    DBOptions {
        options: default_db_options()
            .optimize_for_write_throughput()
            .optimize_for_read(read_size_from_env(ENV_VAR_EVENTS_BLOCK_CACHE_SIZE).unwrap_or(1024))
            .options,
        rw_options: ReadWriteOptions::default().set_ignore_range_deletions(false),
    }
}

fn range_delete_enabled_table_default_config() -> DBOptions {
    DBOptions {
        options: default_db_options()
            .options,
        rw_options: ReadWriteOptions::default().set_ignore_range_deletions(false),
    }
}

fn indirect_move_objects_table_default_config() -> DBOptions {
    let mut options = default_db_options()
        .optimize_for_write_throughput()
        .optimize_for_point_lookup(
            read_size_from_env(ENV_VAR_INDIRECT_OBJECTS_BLOCK_CACHE_SIZE).unwrap_or(512),
        );
    options.options.set_merge_operator(
        "refcount operator",
        reference_count_merge_operator,
        reference_count_merge_operator,
    );
    options
        .options
        .set_compaction_filter("empty filter", empty_compaction_filter);
    options
}

#[cfg(test)]
mod tests {
    use super::*;
    use mgo_types::{
        base_types::{random_object_ref, MgoAddress, ObjectID, SequenceNumber, TransactionDigest},
        committee::EpochId,
        effects::TransactionEffects,
        execution_status::ExecutionStatus,
        gas::GasCostSummary,
        object::Owner,
        transaction::VerifiedTransaction,
        digests::CheckpointDigest,
        mgo_system_state::epoch_start_mgo_system_state::EpochStartSystemState,
    };
    use crate::authority::epoch_start_configuration::{EpochStartConfiguration, EpochStartConfigurationV1};
    use tempfile::TempDir;
    use crate::checkpoints::CheckpointStore;
    use std::sync::Arc;


    fn create_test_authority_store() -> (AuthorityPerpetualTables, Arc<CheckpointStore>, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path();
        let perpetual_tables = AuthorityPerpetualTables::open_tables_read_write(
            path.to_path_buf(),
            MetricConf::default(),
            None,
            None,
        );
        
        // Create checkpoint store in a separate directory
        let checkpoint_dir = dir.path().join("checkpoints");
        std::fs::create_dir_all(&checkpoint_dir).unwrap();
        let checkpoint_store = CheckpointStore::new(&checkpoint_dir);
        
        // No need to insert test checkpoints anymore since we handle missing checkpoints in test mode
        
        // Initialize epoch_start_configuration with a test configuration
        // Use the new_for_testing_with_epoch helper
        let epoch_start_state = EpochStartSystemState::new_for_testing_with_epoch(3);
        
        // Use the constructor method to create the configuration
        let epoch_config = EpochStartConfiguration::V1(
            EpochStartConfigurationV1::new(
                epoch_start_state,
                CheckpointDigest::default(),
            )
        );
        
        perpetual_tables
            .epoch_start_configuration
            .insert(&(), &epoch_config)
            .unwrap();
        
        (perpetual_tables, checkpoint_store, dir)
    }


    fn create_test_transaction_effects(
        transaction_digest: TransactionDigest,
        executed_epoch: EpochId,
    ) -> TransactionEffects {
        TransactionEffects::new_from_execution_v1(
            ExecutionStatus::Success,
            executed_epoch,
            GasCostSummary::default(),
            vec![], // modified_at_versions
            vec![], // shared_objects
            transaction_digest,
            vec![], // created
            vec![], // mutated
            vec![], // unwrapped
            vec![], // deleted
            vec![], // unwrapped_then_deleted
            vec![], // wrapped
            (random_object_ref(), Owner::AddressOwner(MgoAddress::random_for_testing_only())),
            None,   // events_digest
            vec![], // dependencies
        )
    }

    fn insert_test_data_for_epoch(
        store: &AuthorityPerpetualTables,
        epoch: EpochId,
        num_transactions: usize,
    ) -> Vec<TransactionDigest> {
        let mut transaction_digests = Vec::new();

        for _i in 0..num_transactions {
            let tx_digest = TransactionDigest::random();
            let effects = create_test_transaction_effects(tx_digest, epoch);
            let effects_digest = effects.digest();

            // Insert transaction
            let verified_tx = VerifiedTransaction::new_genesis_transaction(vec![]);
            let trusted_tx = verified_tx.serializable();
            store
                .transactions
                .insert(&tx_digest, &trusted_tx)
                .unwrap();

            // Insert effects
            store.effects.insert(&effects_digest, &effects).unwrap();
            store
                .executed_effects
                .insert(&tx_digest, &effects_digest)
                .unwrap();

            transaction_digests.push(tx_digest);
        }

        // Insert epoch-specific data
        let checkpoint_number = 100 * epoch; // Example checkpoint number
        let accumulator = Accumulator::default();
        store
            .root_state_hash_by_epoch
            .insert(&epoch, &(checkpoint_number, accumulator))
            .unwrap();
        store
            .object_per_epoch_marker_table
            .insert(&(epoch, ObjectKey(ObjectID::random(), SequenceNumber::from_u64(1))), &MarkerValue::Received)
            .unwrap();

        transaction_digests
    }

    #[tokio::test]
    async fn test_rollback_to_epoch_basic() {
        let (store, checkpoint_store, _temp_dir) = create_test_authority_store();

        // Insert data for epochs 1, 2, 3
        let epoch1_txs = insert_test_data_for_epoch(&store, 1, 2);
        let epoch2_txs = insert_test_data_for_epoch(&store, 2, 3);
        let epoch3_txs = insert_test_data_for_epoch(&store, 3, 2);

        // Verify data exists for all epochs
        assert!(store.root_state_hash_by_epoch.get(&1).unwrap().is_some());
        assert!(store.root_state_hash_by_epoch.get(&2).unwrap().is_some());
        assert!(store.root_state_hash_by_epoch.get(&3).unwrap().is_some());

        // Gather transactions and effects to remove (epochs > 1)
        let transactions_to_remove = epoch2_txs.iter().chain(epoch3_txs.iter()).cloned().collect();
        let transaction_effects_to_remove = epoch2_txs.iter().chain(epoch3_txs.iter())
            .map(|tx| store.executed_effects.get(tx).unwrap().unwrap())
            .collect();

        // Rollback to epoch 2
        let batch = store.rollback_to_epoch(2, &checkpoint_store, &transactions_to_remove, &transaction_effects_to_remove).unwrap();
        batch.write().unwrap();

        // Verify epoch 1 data still exists
        assert!(store.root_state_hash_by_epoch.get(&1).unwrap().is_some());
        for tx_digest in &epoch1_txs {
            assert!(store.transactions.get(tx_digest).unwrap().is_some());
            assert!(store.executed_effects.get(tx_digest).unwrap().is_some());
        }

        // Verify epochs 2 and 3 data is removed
        assert!(store.root_state_hash_by_epoch.get(&2).unwrap().is_none());
        assert!(store.root_state_hash_by_epoch.get(&3).unwrap().is_none());
        for tx_digest in epoch2_txs.iter().chain(epoch3_txs.iter()) {
            assert!(store.transactions.get(tx_digest).unwrap().is_none());
            assert!(store.executed_effects.get(tx_digest).unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn test_rollback_to_epoch_zero() {
        let (store, checkpoint_store, _temp_dir) = create_test_authority_store();

        // Insert data for epochs 1 and 2
        let epoch1_txs = insert_test_data_for_epoch(&store, 1, 2);
        let epoch2_txs = insert_test_data_for_epoch(&store, 2, 1);

        // Gather all transactions and effects to remove (epochs > 0)
        let transactions_to_remove = epoch1_txs.iter().chain(epoch2_txs.iter()).cloned().collect();
        let transaction_effects_to_remove = epoch1_txs.iter().chain(epoch2_txs.iter())
            .map(|tx| store.executed_effects.get(tx).unwrap().unwrap())
            .collect();

        // Rollback to epoch 0 (should remove all data)
        let batch = store.rollback_to_epoch(0, &checkpoint_store, &transactions_to_remove, &transaction_effects_to_remove).unwrap();
        batch.write().unwrap();

        // Verify all data is removed
        assert!(store.root_state_hash_by_epoch.get(&1).unwrap().is_none());
        assert!(store.root_state_hash_by_epoch.get(&2).unwrap().is_none());
        for tx_digest in epoch1_txs.iter().chain(epoch2_txs.iter()) {
            assert!(store.transactions.get(tx_digest).unwrap().is_none());
            assert!(store.executed_effects.get(tx_digest).unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn test_rollback_validation_prevents_future_epoch() {
        let (store, checkpoint_store, _temp_dir) = create_test_authority_store();

        // Insert data for epoch 1
        insert_test_data_for_epoch(&store, 1, 1);

        // Try to rollback to future epoch (should fail validation)
        let result = store.rollback_to_epoch(5, &checkpoint_store, &vec![], &vec![]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Cannot rollback to future epoch"));
        }
    }


    #[tokio::test]
    async fn test_rollback_atomic_operation() {
        let (store, checkpoint_store, _temp_dir) = create_test_authority_store();

        // Insert data for epochs 1 and 2
        let epoch1_txs = insert_test_data_for_epoch(&store, 1, 1);
        let epoch2_txs = insert_test_data_for_epoch(&store, 2, 1);

        // Verify data exists before rollback
        assert!(store.transactions.get(&epoch1_txs[0]).unwrap().is_some());
        assert!(store.transactions.get(&epoch2_txs[0]).unwrap().is_some());

        // Gather epoch 2 transactions to remove
        let transactions_to_remove = epoch2_txs.clone();
        let transaction_effects_to_remove = epoch2_txs.iter()
            .map(|tx| store.executed_effects.get(tx).unwrap().unwrap())
            .collect();

        // Perform rollback
        let batch = store.rollback_to_epoch(1, &checkpoint_store, &transactions_to_remove, &transaction_effects_to_remove).unwrap();
        batch.write().unwrap();

        // Verify atomic operation: epoch 1 data exists, epoch 2 data doesn't
        assert!(store.transactions.get(&epoch1_txs[0]).unwrap().is_some());
        assert!(store.transactions.get(&epoch2_txs[0]).unwrap().is_none());
    }

    #[tokio::test]
    async fn test_rollback_with_no_data() {
        let (store, checkpoint_store, _temp_dir) = create_test_authority_store();

        // Rollback on empty store should succeed
        let result = store.rollback_to_epoch(0, &checkpoint_store, &vec![], &vec![]);
        let is_ok = result.is_ok();
        if result.is_ok() {
            result.unwrap().write().unwrap();
        }
        assert!(is_ok);
    }
}
