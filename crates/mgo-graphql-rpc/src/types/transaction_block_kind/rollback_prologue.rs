
// Copyright (c) MangoNet Labs Ltd.
// SPDX-License-Identifier: Apache-2.0

use crate::types::epoch::Epoch;
use async_graphql::*;
use mgo_types::messages_checkpoint::CheckpointSequenceNumber;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RollbackPrologueTransaction {
    pub epoch: u64,
    pub checkpoint_sequence_number: CheckpointSequenceNumber,
    /// The checkpoint sequence number this was viewed at.
    pub checkpoint_viewed_at: u64,
}

/// System transaction that marks the beginning of a rollback operation for epoch recovery.
#[Object]
impl RollbackPrologueTransaction {
    /// Epoch being rolled back to.
    async fn epoch(&self, ctx: &Context<'_>) -> Result<Option<Epoch>> {
        Epoch::query(
            ctx.data_unchecked(),
            Some(self.epoch),
            Some(self.checkpoint_viewed_at),
        )
        .await
        .extend()
    }

    /// Checkpoint sequence number for this rollback operation.
    async fn checkpoint_sequence_number(&self) -> u64 {
        self.checkpoint_sequence_number
    }

}