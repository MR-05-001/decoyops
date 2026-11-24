# Egress isolation fix plan

## Finding

`src-tauri/src/firewall.rs` has a Linux `NftablesBackend` that returns `Ok(())` for both deny and allow operations without invoking `nft`. Deployment therefore proceeds while the managed decoy subnet has no egress rule. In `docker.rs`, subnet inspection failure also falls back to the literal `unknown`, which is passed to the firewall backend instead of failing closed.

## Proposed changes (pending review)

1. Make network inspection required for managed decoys: validate the discovered subnet as an IP network and abort deployment, removing the newly created network on failure, if it is absent or invalid. Preserve the explicit unmanaged-network bypass.
2. Implement Linux nftables operations with argument-based process execution (no shell interpolation). Create/verify the DecoyOps table and forwarding chain idempotently, install a subnet-scoped drop rule, and return an error on any command failure. Keep unrelated host forwarding unaffected; do not set a global forward-chain drop policy.
3. Ensure any opt-in allow rule is validated and narrowly scoped to one container IP and requested TCP destination ports, and that its ordering/semantics do not accidentally permit the rest of the subnet. Do not enable C2 observation by default.
4. Add unit tests for invalid network/IP/port inputs and command construction/failure behavior using an injectable command runner or equivalent test seam, without requiring root or changing the host firewall in tests.
5. Run Rust formatting, focused tests, and clippy for the Tauri crate. Review rollback behavior so failed firewall setup never allows a managed container to start.

## Scope and constraints

- Likely files: `src-tauri/src/firewall.rs`, `src-tauri/src/docker.rs`, and relevant Rust tests.
- No changes to unmanaged-network behavior or other security controls.
- Windows PowerShell firewall behavior will be left unchanged in this focused fix unless review identifies that as the reported platform-specific bug; the verified no-op is the Linux backend.
- Existing unrelated worktree change `D tools/frp/frpc.exe` will be preserved.

## Status: Implemented & Verified

All proposed changes have been implemented:
1. **Network inspection required:** In `docker.rs`, `inspect_network` is required for managed decoys; subnet is validated via `validate_subnet_cidr`, and deployment fails closed (rolling back the network) if invalid or absent.
2. **Linux nftables operations:** `NftablesBackend` in `src-tauri/src/firewall.rs` uses argument-based execution with `NftCommandRunner`, creates the `inet decoyops` table and `decoy_egress` chain idempotently, and installs subnet-scoped drop rules with `remove_egress_drop` on container termination.
3. **Narrow opt-in allow rules:** Container IP and destination ports are strictly validated in `allow_egress_ports` and inserted before the drop rule.
4. **Automated unit tests:** Comprehensive test coverage with `MockNftRunner` tests valid/invalid CIDRs, idempotent drop rules, single-IP allow rules, command failures, and rule deletion.
