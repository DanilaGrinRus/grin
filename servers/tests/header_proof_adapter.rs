//! Server-side tests for `NetToChainAdapter::get_header_proofs`.
//!
//! The fixture is a real `Chain` (temporary chain store + header PMMR) with a
//! small synthetic header MMR. It deliberately does not use a live node.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use grin_chain::types::{NoopAdapter, SyncState};
use grin_chain::Chain;
use grin_core::consensus;
use grin_core::core::hash::Hashed;
use grin_core::core::pmmr::{ReadablePMMR, ReadonlyPMMR, PMMR};
use grin_core::core::BlockHeader;
use grin_core::global;
use grin_core::pow::{Difficulty, Proof, ProofOfWork};
use grin_p2p::header_proof::{verify_header_proof_item, verify_memberships};
use grin_p2p::types::{Capabilities, Direction, PeerAddr, PeerInfo, PeerLiveInfo};
use grin_p2p::ChainAdapter;
use grin_p2p::MAX_HEADER_PROOF_ITEMS;
use grin_pool::types::{NoopPoolAdapter, PoolConfig};
use grin_pool::TransactionPool;
use grin_servers::common::adapters::{NetToChainAdapter, PoolToChainAdapter};
use grin_servers::common::types::ServerConfig;
use grin_util::RwLock;

fn temp_chain_dir() -> String {
	let mut p = std::env::temp_dir();
	p.push(format!(
		"grin-header-proof-test-{}-{}",
		std::process::id(),
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_nanos()
	));
	p.to_string_lossy().to_string()
}

fn test_header(height: u64, prev_root: grin_core::core::hash::Hash) -> BlockHeader {
	BlockHeader {
		height,
		version: consensus::header_version(height),
		prev_root,
		pow: ProofOfWork {
			// Header hashing in hash mode commits only to the PoW; give each
			// synthetic header a distinct (height-derived) proof so hashes and
			// MMR leaves are distinct.
			proof: Proof::new(vec![height; global::proofsize()]),
			..Default::default()
		},
		..Default::default()
	}
}

/// Builds a real `Chain` whose header PMMR contains `count` synthetic headers.
/// Headers are saved in the chain store and the header PMMR is extended
/// directly; this keeps the fixture small without mining real blocks.
fn header_chain(count: u64) -> (Arc<Chain>, Vec<BlockHeader>) {
	global::set_local_chain_type(grin_core::global::ChainTypes::AutomatedTesting);
	let dir = temp_chain_dir();
	let genesis = grin_core::genesis::genesis_dev();
	let chain = Arc::new(
		Chain::init(
			dir,
			Arc::new(NoopAdapter {}),
			genesis,
			grin_core::pow::verify_size,
			false,
			None,
		)
		.expect("init chain"),
	);

	let mut headers = vec![chain.genesis()];
	let pmmr_handle = chain.header_pmmr();
	for height in 1..count {
		let mut handle = pmmr_handle.write();
		let prev_root = ReadonlyPMMR::at(&handle.backend, handle.size)
			.root()
			.expect("historical root");
		let header = test_header(height, prev_root);
		{
			let store = chain.store();
			let mut batch = store.batch().expect("store batch");
			batch.save_block_header(&header).expect("save header");
			batch.commit().expect("commit header");
		}
		let size = handle.size;
		let mut pmmr = PMMR::at(&mut handle.backend, size);
		pmmr.push(&header).expect("push header");
		handle.size = pmmr.size;
		headers.push(header);
	}
	(chain, headers)
}

fn peer_info(port: u16) -> PeerInfo {
	PeerInfo {
		capabilities: Capabilities::default(),
		user_agent: "header-proof-test".to_owned(),
		version: grin_core::ser::ProtocolVersion::local(),
		addr: PeerAddr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
		direction: Direction::Outbound,
		live_info: Arc::new(RwLock::new(PeerLiveInfo::new(Difficulty::zero()))),
	}
}

fn adapter(chain: &Arc<Chain>) -> NetToChainAdapter<PoolToChainAdapter, NoopPoolAdapter> {
	let pool_chain = Arc::new(PoolToChainAdapter::new());
	pool_chain.set_chain(chain.clone());
	let pool = Arc::new(RwLock::new(TransactionPool::new(
		PoolConfig::default(),
		pool_chain.clone(),
		Arc::new(NoopPoolAdapter {}),
	)));
	NetToChainAdapter::<PoolToChainAdapter, NoopPoolAdapter>::new(
		Arc::new(SyncState::new()),
		chain.clone(),
		pool,
		ServerConfig::default(),
		vec![],
	)
}

#[test]
fn valid_request_returns_request_bound_verified_proofs() {
	let (chain, headers) = header_chain(1000);
	let adapter = adapter(&chain);
	let anchor = headers[900].clone();
	let heights = vec![0u64, 1, 2, 7, 8, 31, 63, 511, 899];
	let response = adapter
		.get_header_proofs(anchor.hash(), &heights, &peer_info(41001))
		.expect("request")
		.expect("proofs");

	assert_eq!(response.anchor, anchor.hash());
	assert_eq!(
		response
			.items
			.iter()
			.map(|i| i.header.height)
			.collect::<Vec<_>>(),
		heights
	);
	verify_memberships(&anchor, &response).expect("client verification");
	for item in &response.items {
		verify_header_proof_item(
			anchor.prev_root,
			response.mmr_size,
			item.header.height,
			&item.header,
			&item.path,
		)
		.expect("individual client verification");
	}
}

#[test]
fn invalid_height_sets_are_rejected() {
	let (chain, headers) = header_chain(1000);
	let adapter = adapter(&chain);
	let anchor = headers[900].clone();

	assert!(
		adapter
			.get_header_proofs(anchor.hash(), &[], &peer_info(41002))
			.unwrap()
			.is_none(),
		"empty request must be rejected"
	);
	assert!(
		adapter
			.get_header_proofs(anchor.hash(), &[10, 10], &peer_info(41003))
			.unwrap()
			.is_none(),
		"duplicate heights must be rejected"
	);
	assert!(
		adapter
			.get_header_proofs(anchor.hash(), &[10, 9], &peer_info(41004))
			.unwrap()
			.is_none(),
		"unsorted heights must be rejected"
	);
	assert!(
		adapter
			.get_header_proofs(anchor.hash(), &[900], &peer_info(41005))
			.unwrap()
			.is_none(),
		"height == anchor must be rejected"
	);
	assert!(
		adapter
			.get_header_proofs(anchor.hash(), &[901], &peer_info(41006))
			.unwrap()
			.is_none(),
		"height > anchor must be rejected"
	);
}

#[test]
fn max_and_over_limit_requests() {
	let (chain, headers) = header_chain(MAX_HEADER_PROOF_ITEMS as u64 + 100);
	let adapter = adapter(&chain);
	let anchor = headers[(MAX_HEADER_PROOF_ITEMS + 50) as usize].clone();
	let max_heights: Vec<u64> = (0..MAX_HEADER_PROOF_ITEMS).map(u64::from).collect();
	let too_many: Vec<u64> = (0..MAX_HEADER_PROOF_ITEMS + 1).map(u64::from).collect();

	let max = adapter
		.get_header_proofs(anchor.hash(), &max_heights, &peer_info(41007))
		.expect("request")
		.expect("max request must be served");
	assert_eq!(max.items.len(), MAX_HEADER_PROOF_ITEMS as usize);
	verify_memberships(&anchor, &max).expect("max request verifies");

	assert!(
		adapter
			.get_header_proofs(anchor.hash(), &too_many, &peer_info(41008))
			.unwrap()
			.is_none(),
		"request above MAX_HEADER_PROOF_ITEMS must be rejected"
	);
}

#[test]
fn unknown_and_side_branch_anchors_are_rejected() {
	let (chain, headers) = header_chain(1000);
	let adapter = adapter(&chain);
	let main_anchor = headers[900].clone();

	assert!(
		adapter
			.get_header_proofs(
				grin_core::core::hash::ZERO_HASH,
				&[1, 2, 3],
				&peer_info(41009)
			)
			.unwrap()
			.is_none(),
		"unknown anchor must be rejected"
	);

	// A header stored at the same height but not on the header MMR is a side
	// branch and must not be accepted as an anchor.
	let mut side = test_header(main_anchor.height, grin_core::core::hash::ZERO_HASH);
	side.timestamp = main_anchor.timestamp;
	side.pow.proof = Proof::new(vec![main_anchor.height + 1; global::proofsize()]);
	let store = chain.store();
	let mut batch = store.batch().expect("store batch");
	batch.save_block_header(&side).expect("save side header");
	batch.commit().expect("commit side header");
	assert_ne!(side.hash(), main_anchor.hash());
	assert!(
		adapter
			.get_header_proofs(side.hash(), &[1, 2, 3], &peer_info(41010))
			.unwrap()
			.is_none(),
		"side-branch anchor must be rejected"
	);
}

#[test]
fn repeated_request_is_stable() {
	let (chain, headers) = header_chain(1000);
	let adapter = adapter(&chain);
	let anchor = headers[950].clone();
	let heights = vec![3u64, 19, 42, 700, 949];
	let first = adapter
		.get_header_proofs(anchor.hash(), &heights, &peer_info(41011))
		.expect("request")
		.expect("proofs");
	let second = adapter
		.get_header_proofs(anchor.hash(), &heights, &peer_info(41012))
		.expect("request")
		.expect("proofs");
	assert_eq!(first.anchor, second.anchor);
	assert_eq!(first.mmr_size, second.mmr_size);
	assert_eq!(first.items.len(), second.items.len());
	for (a, b) in first.items.iter().zip(second.items.iter()) {
		assert_eq!(a.header, b.header);
		assert_eq!(a.path, b.path);
	}
}

#[test]
fn tampered_proof_fails_client_verification() {
	let (chain, headers) = header_chain(1000);
	let adapter = adapter(&chain);
	let anchor = headers[900].clone();
	let heights = vec![0u64, 1, 500, 899];
	let mut response = adapter
		.get_header_proofs(anchor.hash(), &heights, &peer_info(41013))
		.expect("request")
		.expect("proofs");

	// Replace the path of one item with a valid path for a different height
	// (or simply corrupt it) and require the client verifier to reject it.
	if let Some(path) = response.items[2].path.first_mut() {
		*path = grin_core::core::hash::ZERO_HASH;
	} else {
		response.items[2]
			.path
			.push(grin_core::core::hash::ZERO_HASH);
	}
	assert!(verify_memberships(&anchor, &response).is_err());
}
