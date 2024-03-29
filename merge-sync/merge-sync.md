# Sync & The Merge

****Warning!**** This is a work in progress. After initial review, it seems that the sync scheme presented here will not work without modifications. See end of document for known issues and potential solutions. For now, you should read this as a description of the ideal sync algorithm, keeping in mind that it will become more complicated later.

In this document, we (the geth team) present our ideas for implementing chain synchronization on the merged eth1 + eth2 chain. After the merge event, eth1 and eth2 clients run in tandem. The eth2 client maintains the connection to the beacon chain and performs fork choice. The eth1 client, a.k.a. the 'execution layer', receives block data from the eth2 client, executes/verifies it and maintains the application state.

The interface that eth2 and eth1 use to communicate is uni-directional: all cross-client communication is initiated by eth2, and happens in the form of requests. Eth1 responds to requests, but cannot request any information from eth2.


## Definitions

In the text below, we refer to beacon chain blocks as b<sub>x</sub>. We also assume that the beacon chain begins at block b<sub>W</sub>, a recent checkpoint, which must be a block after the merge event. There is a direct correspondence between beacon chain blocks and block data of the execution layer: for every beacon block b<sub>x</sub> (for x >= w), a corresponding execution-layer block B<sub>x</sub> also exists. Additionally, every execution-layer block B<sub>x</sub> contains its block header H<sub>x</sub>.

Please note that this document is an abstract description of the sync algorithm and isn't concerned with the real APIs that eth1 and eth2 nodes will use to communicate. We assume that eth2 can invoke the following operations in the eth1 client:

-   **checkpoint(H):** notifies the eth1 client about a checkpoint header. This has no useful response.
-   **final(B):** submits a finalized block. The eth1 client can answer 'old', 'syncing', invalid(B) or synced(B). Note that we assume this will be called for all finalized blocks, not just on epoch boundaries.
-   **proc(B):** submits a non-finalized block for EVM processing. The eth1 client can respond with 'valid', 'invalid' or 'syncing'.

In diagrams, not all responses to eth2 requests are shown.


## Sync


### eth2 perspective

This section explains the sync procedure from the eth2 client point-of-view.

When the eth2 client starts, it is initialized with a 'weak subjectivity checkpoint' containing the beacon chain state of a historical block b<sub>W</sub>. The checkpoint also contains the execution-layer block header H<sub>W</sub>. On startup, H<sub>W</sub> is immediately relayed to the eth1 client (1).

To sync, the eth2 client must first process the beacon chain optimistically&#x2014;without accessing application state&#x2014;up to the latest finalized block b<sub>F</sub> (2). When block b<sub>F</sub> is reached, the eth2 client starts eth1 sync by providing the execution-layer block B<sub>F</sub> to the eth1 client (3).

![img](./img/beacon-1.svg "Syncing up to the latest finalized block")

The eth2 client keeps following the beacon chain until eth1 sync completes, and keeps submitting finalized blocks to the eth1 client. This means it should repeat step (3) for every new finalized block.

Eth1 sync will usually take quite a bit of time to complete. While it is syncing, the beacon chain advances by t blocks to the latest finalized block b<sub>F+t</sub>.

The eth1 client signals that it is done by responding with synced(B<sub>F+t</sub>) (4). The application state of B<sub>F+t</sub> is now available and the eth2 client can perform additional cross-validation against this state. For example, it could read the deposit contract here.

The eth2 client should now submit the execution-layer block data of all non-finalized beacon blocks to the eth1 client for processing (5). The sync procedure completes when the current head block b<sub>H</sub> is reached.

![img](./img/beacon-2.svg "Processing non-finalized blocks")


### eth1 perspective

Upon startup, the eth1 client first waits for a checkpoint header H<sub>W</sub> from the eth2 client. H<sub>W</sub> must be a descendant of the genesis block B<sub>G</sub>.

Sync begins when the finalized block B<sub>F</sub> is received. This block is assumed to be valid. Furthermore, it is assumed that B<sub>F</sub> is a descendant of B<sub>W</sub>.

While the chain is downloading/processing, the eth1 client receives further notifications about newly-finalized blocks in range B<sub>F+1</sub>&#x2026;B<sub>F+t</sub>. During sync, at latest finalized block B<sub>f</sub>, clients must handle final(B<sub>x</sub>) as follows:

-   for x <= f, the response is 'old' if the block is known, or invalid(B<sub>x</sub>) if the block is unknown.
-   for x > f+1, attempting to finalize an unknown future block, sync is restarted on B<sub>x</sub> and the response is 'syncing'.
-   for x == f+1, the block is appended to the database. If the client is still busy syncing to B<sub>f</sub>, the response is 'syncing'. If the client is done syncing to block B<sub>f</sub>, it processes block B<sub>x</sub> and outputs synced(B<sub>x</sub>) or invalid(B<sub>x</sub>).

When proc() is received during sync, the response is 'syncing'.

![img](./img/eth1-1.svg "Downloading the finalized eth1 chain")

After starting sync on B<sub>F</sub> (1), the eth1 client first downloads the chain of block headers down from H<sub>F</sub>, following parent hashes (2). Headers are written to the database. The header chain must contain the checkpoint header H<sub>W</sub>, and sync fails if a different header is encountered at the same block number. This sanity check exists to ensure that the chain is valid without having to sync all the way back to the genesis block.

When the genesis header H<sub>G</sub> is reached, block body data can be downloaded (3). There are two ways to do this:

-   The client can perform 'full sync', downloading blocks and executing their state transitions. This recreates the application state incrementally up to the latest block. Sync is complete when the latest finalized block B<sub>F+t</sub> has been processed.

-   The client can perform state synchronization by downloading the blocks B<sub>G+1</sub>&#x2026;B<sub>F</sub> and their application state without EVM execution. This is expected to be faster than full sync, and is equally secure because the state root of B<sub>F</sub> was finalized by eth2. The state download can happen concurrently with steps (2) and (3).
    
    The peer-to-peer network can only provide the state of very recent blocks. Since it is expected that the state of B<sub>F</sub> will gradually become unavailable as the chain advances, the client must occasionally re-target its state sync to a more recent 'pivot block'. Conveniently, the newly-finalized blocks B<sub>F+1</sub>&#x2026;B<sub>F+t</sub> received from eth2 can be used for this purpose. You can read more about the pivot block in the [snap sync protocol specification](https://github.com/ethereum/devp2p/blob/master/caps/snap.md#synchronization-algorithm).

After reporting sync completion of B<sub>F+t</sub> to the eth2 client (4), the execution layer is done and switches to its ordinary mode of operation: individual blocks are received from the eth2 client, the blocks are processed, and their validity reported back to the eth2 client. Reorgs of non-finalized blocks may also be triggered after sync has completed. Reorg handling is discussed later in this document.


### Handling restarts and errors

The above description of sync focuses on a single sync cycle. In order to be robust against failures, and to handle client restarts, clients must be able to perform multiple sync cycles with an initialized database. The interface between eth2 and eth1 makes this easy for eth2 because it is uni-directional: When eth2 restarts, it can simply perform the usual request sequence and expect that the eth1 client will reset itself to the correct state.

When eth1 receives note of a finalized block B<sub>F</sub>, there are two possibilities: if the block already exists in the local chain, and its application state is also available, sync isn't necessary. If the finalized block is unknown, the eth1 client should restart sync at step (1), downloading parent headers in reverse. If the block is known but its state is unavailable, the client should attempt to synchronize the state of B<sub>F</sub> or, when configured for full sync, attempt to process blocks forward up to B<sub>F</sub> from the most recent available state.

For eth1 sync restarts, block data persisted to the database by previous sync cycles can be reused. Whenever a finalized header H<sub>x</sub> is to be fetched from the network, the client should check if the database already contains block data at the same block height x. If the local database contains a finalized header at height x, but its hash does not match H<sub>x</sub>, the client should delete the header and all block data associated with it. If the hash of the previously-stored header does match H<sub>x</sub>, sync can skip over the chain of locally available headers and resume sync at the height of the next unavailable header.

To make this skipping operation work efficiently, we recommend that clients store and maintain 'marker' records containing information about previously-stored contiguous chain segments. When sync starts at H<sub>F</sub>, the client stores marker M<sub>F</sub> = F. As subsequent headers H<sub>x</sub> are downloaded, the marker is updated to M<sub>F</sub> = x. Similarly, as the chain is extended forward by concurrent calls to final(B<sub>F+1</sub>), the marker also moves forward, i.e. M<sub>F+1</sub> = M<sub>F</sub> and M<sub>F</sub> is deleted.

Now assume that the sync cycle terminates unexpectedly at block height s. When the next cycle starts, it first loads marker records of previous sync cycles. As the new cycle progresses downloading parents, it will eventually cross the previous height F. If the header hash matches the previously-stored header H<sub>F</sub>, the marker can be used to resume sync at height s where the first cycle left off.


## Reorg processing and state availability

It is common knowledge that the application state of eth1 can become quite large. As such, eth1 clients usually only store exactly one full copy of this state.

In order to make state synchronization work, the application state of the latest finalized block B<sub>F</sub> must be available for download. We therefore recommend that clients which store exactly one full copy of the state should store the state of B<sub>F</sub>.

For the tree of non-finalized blocks beyond B<sub>F</sub>, the state diff of each block can be held in main memory. As new blocks are finalized, the client applies their diffs to the database, moving the persistent state forward. Storing diffs in memory allows for efficient reorg processing: when the eth2 client detects a reorg from block b<sub>x</sub> to block b<sub>y</sub>, it first determines the common ancestor b<sub>a</sub>. It can then submit all blocks B<sub>a+1</sub>&#x2026;B<sub>y</sub> for processing. When the eth1 client detects that a block has already been processed because its state is available as a diff in memory, it can skip EVM processing of the block and just move its head state reference to the new block.

While reorgs below B<sub>F</sub> cannot happen during normal operation of the beacon chain, it may still be necessary to roll back to an earlier state when EVM processing flaws cause the client to deviate from the canonical chain. As a safety net for this exceptional case, we recommend that eth1 clients to maintain a way to manually reorg up to 90,000 blocks (roughly 2 weeks), as this would provide sufficient time to fix issues.

To make this 'manual intervention reorg' work, eth1 client can maintain backward diffs in a persistent store. If an intervention is requested, these diffs can be incrementally applied to the state of B<sub>F</sub>, resetting the client to an earlier state.


## Issues

In early review of this scheme, two issues were discovered. Both stem from our misunderstanding of eth2 finalization semantics.

(1) Since eth2 finalizes blocks only on epoch boundaries, it wants to call final(B) only for epoch blocks. This could be handled a bit better by also using proc(B) in the sync trigger.

(2) While finalization will work within ~64 blocks in the happy case, it can take up to 2 weeks to finalize in the event of a network partition. Since the maximum number of non-finalized blocks is so much larger than we initially anticipated, it will not be possible to use B<sub>F</sub> as the persistent state block.

We have decided to tackle this issue in the following way:

-   At head H, define the 'calcified' block B<sub>C</sub> with C = max(H-512, F). This puts an upper bound of 512 blocks on the number of states kept in memory.
-   Define that clients should keep the state of B<sub>C</sub> in persistent storage.
-   Use B<sub>C</sub> as the initial sync target. This has implications on the sync trigger because the eth1 client can no longer rely on final(B) to start sync (B<sub>C</sub> may be non-final).
-   Add a new call ****reset(B)**** to reset the eth1 client to a historical block. Require that clients must be able to satisfy any reset in range B<sub>F</sub>&#x2026;B<sub>H</sub>. They will probably have to implement something like the persistent reverse diffs recommended in the reorg section.

Adding the calcified block also adds some tricky new corner cases and failure modes. In particular, if the eth1 client just performed snap sync, it will not be able to reorg below B<sub>C</sub>, because reverse diffs down to B<sub>F</sub> will not be available. We may solve this by recommending that nodes should attempt snap sync if reset(B) cannot be satisfied. For sure, some nodes will be synced enough to serve the target state. In the absolute worst case, we need to make reverse diffs available for download in snap sync.
