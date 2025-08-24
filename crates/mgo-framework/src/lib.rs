// Copyright (c) MangoNet Labs Ltd.
// SPDX-License-Identifier: Apache-2.0

use move_binary_format::compatibility::Compatibility;
use move_binary_format::file_format::{Ability, AbilitySet};
use move_binary_format::CompiledModule;
use move_core_types::gas_algebra::InternalGas;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fmt::Formatter;
use mgo_types::base_types::ObjectRef;
use mgo_types::storage::ObjectStore;
use mgo_types::{base_types::ObjectID, digests::TransactionDigest, move_package::MovePackage, object::{Object, OBJECT_START_VERSION}, MOVE_STDLIB_PACKAGE_ID, MGO_FRAMEWORK_PACKAGE_ID, MGO_SYSTEM_PACKAGE_ID, MGO_INSCRIPTION_PACKAGE_ID};
use tracing::{error, info};

/// Represents a system package in the framework, that's built from the source code inside
/// mgo-framework.
#[derive(Clone, Serialize, PartialEq, Eq, Deserialize)]
pub struct SystemPackage {
    pub id: ObjectID,
    pub bytes: Vec<Vec<u8>>,
    pub dependencies: Vec<ObjectID>,
}

impl SystemPackage {
    pub fn new(id: ObjectID, raw_bytes: &'static [u8], dependencies: &[ObjectID]) -> Self {
        let bytes: Vec<Vec<u8>> = bcs::from_bytes(raw_bytes).unwrap();
        Self {
            id,
            bytes,
            dependencies: dependencies.to_vec(),
        }
    }

    pub fn id(&self) -> &ObjectID {
        &self.id
    }

    pub fn bytes(&self) -> &[Vec<u8>] {
        &self.bytes
    }

    pub fn dependencies(&self) -> &[ObjectID] {
        &self.dependencies
    }

    pub fn modules(&self) -> Vec<CompiledModule> {
        self.bytes
            .iter()
            .map(|b| CompiledModule::deserialize_with_defaults(b).unwrap())
            .collect()
    }

    pub fn genesis_move_package(&self) -> MovePackage {
        MovePackage::new_system(
            OBJECT_START_VERSION,
            &self.modules(),
            self.dependencies.iter().copied(),
        )
    }

    pub fn genesis_object(&self) -> Object {
        Object::new_system_package(
            &self.modules(),
            OBJECT_START_VERSION,
            self.dependencies.to_vec(),
            TransactionDigest::genesis_marker(),
        )
    }
}

impl std::fmt::Debug for SystemPackage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Object ID: {:?}", self.id)?;
        writeln!(f, "Size: {}", self.bytes.len())?;
        writeln!(f, "Dependencies: {:?}", self.dependencies)?;
        Ok(())
    }
}

macro_rules! define_system_packages {
    ([$(($id:expr, $path:expr, $deps:expr)),* $(,)?]) => {{
        static PACKAGES: Lazy<Vec<SystemPackage>> = Lazy::new(|| {
            vec![
                $(SystemPackage::new(
                    $id,
                    include_bytes!(concat!(env!("OUT_DIR"), "/", $path)),
                    &$deps,
                )),*
            ]
        });
        Lazy::force(&PACKAGES)
    }}
}

pub struct BuiltInFramework;
impl BuiltInFramework {
    pub fn iter_system_packages() -> impl Iterator<Item = &'static SystemPackage> {
        // All system packages in the current build should be registered here, and this is the only
        // place we need to worry about if any of them changes.
        // TODO: Is it possible to derive dependencies from the bytecode instead of manually specifying them?
        define_system_packages!([
            (MOVE_STDLIB_PACKAGE_ID, "move-stdlib", []),
            (
                MGO_FRAMEWORK_PACKAGE_ID,
                "mgo-framework",
                [MOVE_STDLIB_PACKAGE_ID]
            ),
            (
                MGO_SYSTEM_PACKAGE_ID,
                "mgo-system",
                [MOVE_STDLIB_PACKAGE_ID, MGO_FRAMEWORK_PACKAGE_ID]
            ),
            (
                MGO_INSCRIPTION_PACKAGE_ID,
                "mgo-inscription",
                [MOVE_STDLIB_PACKAGE_ID, MGO_FRAMEWORK_PACKAGE_ID]
            )
        ])
        .iter()
    }

    pub fn all_package_ids() -> Vec<ObjectID> {
        Self::iter_system_packages().map(|p| p.id).collect()
    }

    pub fn get_package_by_id(id: &ObjectID) -> &'static SystemPackage {
        Self::iter_system_packages().find(|s| &s.id == id).unwrap()
    }

    pub fn genesis_move_packages() -> impl Iterator<Item = MovePackage> {
        Self::iter_system_packages().map(|package| package.genesis_move_package())
    }

    pub fn genesis_objects() -> impl Iterator<Item = Object> {
        Self::iter_system_packages().map(|package| package.genesis_object())
    }
}

pub const DEFAULT_FRAMEWORK_PATH: &str = env!("CARGO_MANIFEST_DIR");

pub fn legacy_test_cost() -> InternalGas {
    InternalGas::new(0)
}

/// Check whether the framework defined by `modules` is compatible with the framework that is
/// already on-chain (i.e. stored in `object_store`) at `id`.
///
/// - Returns `None` if the current package at `id` cannot be loaded, or the compatibility check
///   fails (This is grounds not to upgrade).
/// - Panics if the object at `id` can be loaded but is not a package -- this is an invariant
///   violation.
/// - Returns the digest of the current framework (and version) if it is equivalent to the new
///   framework (indicates support for a protocol upgrade without a framework upgrade).
/// - Returns the digest of the new framework (and version) if it is compatible (indicates
///   support for a protocol upgrade with a framework upgrade).
pub async fn compare_system_package<S: ObjectStore>(
    object_store: &S,
    id: &ObjectID,
    modules: &[CompiledModule],
    dependencies: Vec<ObjectID>,
    max_binary_format_version: u32,
    no_extraneous_module_bytes: bool,
) -> Option<ObjectRef> {
    info!(
        "COMPARE_SYSTEM_PACKAGE: Starting compatibility check for package {}, {} modules, {} dependencies, max_binary_format_version: {}, no_extraneous_module_bytes: {}",
        id,
        modules.len(),
        dependencies.len(),
        max_binary_format_version,
        no_extraneous_module_bytes
    );
    let cur_object = match object_store.get_object(id) {
        Ok(Some(cur_object)) => cur_object,

        Ok(None) => {
            // creating a new framework package--nothing to check
            info!(
                "COMPARE_SYSTEM_PACKAGE: Package {} not found in object store, creating new system package with version {}",
                id, OBJECT_START_VERSION
            );
            return Some(
                Object::new_system_package(
                    modules,
                    // note: execution_engine assumes any system package with version OBJECT_START_VERSION is freshly created
                    // rather than upgraded
                    OBJECT_START_VERSION,
                    dependencies,
                    // Genesis is fine here, we only use it to calculate an object ref that we can use
                    // for all validators to commit to the same bytes in the update
                    TransactionDigest::genesis_marker(),
                )
                .compute_object_reference(),
            );
        }

        Err(e) => {
            error!("COMPARE_SYSTEM_PACKAGE: Error loading framework object at {id}: {e:?}");
            return None;
        }
    };

    let cur_ref = cur_object.compute_object_reference();
    info!(
        "COMPARE_SYSTEM_PACKAGE: Found existing package {}, version: {}, reference: {:?}",
        id, cur_object.version(), cur_ref
    );
    let cur_pkg = cur_object
        .data
        .try_as_package()
        .expect("Framework not package");
    
    // Print detailed package information
    info!(
        "COMPARE_SYSTEM_PACKAGE: Current package {} details: \n  - Object ID: {}\n  - Version: {}\n  - Previous Transaction: {:?}\n  - Storage Rebate: {}\n  - Module Count: {}\n  - Linkage Table Size: {}\n  - Type Origin Table Size: {}",
        id,
        cur_object.id(),
        cur_object.version(),
        cur_object.previous_transaction,
        cur_object.storage_rebate,
        cur_pkg.serialized_module_map().len(),
        cur_pkg.linkage_table().len(),
        cur_pkg.type_origin_table().len()
    );
    
    // Print module names and sizes
    let mut module_info = Vec::new();
    for (name, module_bytes) in cur_pkg.serialized_module_map() {
        module_info.push(format!("    - {}: {} bytes", name, module_bytes.len()));
    }
    info!(
        "COMPARE_SYSTEM_PACKAGE: Package {} modules:\n{}",
        id,
        module_info.join("\n")
    );
    
    // Print first few bytes of each module for comparison
    for (name, module_bytes) in cur_pkg.serialized_module_map() {
        let preview_len = std::cmp::min(32, module_bytes.len());
        let preview_bytes: Vec<String> = module_bytes[..preview_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        info!(
            "COMPARE_SYSTEM_PACKAGE: Package {} module '{}' first {} bytes: {}",
            id,
            name,
            preview_len,
            preview_bytes.join(" ")
        );
    }

    let mut new_object = Object::new_system_package(
        modules,
        // Start at the same version as the current package, and increment if compatibility is
        // successful
        cur_object.version(),
        dependencies.clone(),
        cur_object.previous_transaction,
    );

    let new_ref = new_object.compute_object_reference();
    
    // Print new package details for comparison
    let new_pkg = new_object
        .data
        .try_as_package()
        .expect("Created as package");
    
    info!(
        "COMPARE_SYSTEM_PACKAGE: New package {} details: \n  - Object ID: {}\n  - Version: {}\n  - Previous Transaction: {:?}\n  - Module Count: {}\n  - Dependencies: {:?}\n  - Linkage Table Size: {}\n  - Type Origin Table Size: {}",
        id,
        new_object.id(),
        new_object.version(),
        new_object.previous_transaction,
        new_pkg.serialized_module_map().len(),
        dependencies,
        new_pkg.linkage_table().len(),
        new_pkg.type_origin_table().len()
    );
    
    // Print new module names and sizes from the package
    let mut new_module_info = Vec::new();
    for (name, module_bytes) in new_pkg.serialized_module_map() {
        new_module_info.push(format!("    - {}: {} bytes", name, module_bytes.len()));
    }
    info!(
        "COMPARE_SYSTEM_PACKAGE: New package {} modules:\n{}",
        id,
        new_module_info.join("\n")
    );
    
    // Print first few bytes of each module for comparison
    for (name, module_bytes) in new_pkg.serialized_module_map() {
        let preview_len = std::cmp::min(32, module_bytes.len());
        let preview_bytes: Vec<String> = module_bytes[..preview_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        info!(
            "COMPARE_SYSTEM_PACKAGE: New package {} module '{}' first {} bytes: {}",
            id,
            name,
            preview_len,
            preview_bytes.join(" ")
        );
    }
    
    if cur_ref == new_ref {
        info!(
            "COMPARE_SYSTEM_PACKAGE: Package {} unchanged, current and new references match: {:?}",
            id, cur_ref
        );
        return Some(cur_ref);
    }
    info!(
        "COMPARE_SYSTEM_PACKAGE: Package {} changed, current ref: {:?}, new ref: {:?}, proceeding with compatibility check",
        id, cur_ref, new_ref
    );

    let compatibility = Compatibility {
        check_struct_and_pub_function_linking: true,
        check_struct_layout: true,
        check_friend_linking: false,
        // Checking `entry` linkage is required because system packages are updated in-place, and a
        // transaction that was rolled back to make way for reconfiguration should still be runnable
        // after a reconfiguration that upgraded the framework.
        //
        // A transaction that calls a system function that was previously `entry` and is now private
        // will fail because its entrypoint became no longer callable. A transaction that calls a
        // system function that was previously `public entry` and is now just `public` could also
        // fail if one of its mutable inputs was being used in another private `entry` function.
        check_private_entry_linking: true,
        disallowed_new_abilities: AbilitySet::singleton(Ability::Key),
        disallow_change_struct_type_params: true,
    };

    let new_pkg = new_object
        .data
        .try_as_package_mut()
        .expect("Created as package");

    let cur_normalized =
        match cur_pkg.normalize(max_binary_format_version, no_extraneous_module_bytes) {
            Ok(v) => v,
            Err(e) => {
                error!("COMPARE_SYSTEM_PACKAGE: Could not normalize existing package {}: {e:?}", id);
                return None;
            }
        };
    let mut new_normalized = match new_pkg
        .normalize(max_binary_format_version, no_extraneous_module_bytes) {
        Ok(normalized) => normalized,
        Err(e) => {
            error!("COMPARE_SYSTEM_PACKAGE: Could not normalize new package {}: {e:?}", id);
            return None;
        }
    };
    info!(
        "COMPARE_SYSTEM_PACKAGE: Package {} normalization successful, checking {} modules for compatibility",
        id, cur_normalized.len()
    );

    for (name, cur_module) in cur_normalized {
        let Some(new_module) = new_normalized.remove(&name) else {
            error!("COMPARE_SYSTEM_PACKAGE: Module {name} missing in new package {id}");
            return None;
        };

        info!("COMPARE_SYSTEM_PACKAGE: Checking compatibility for module {id}::{name}");
        if let Err(e) = compatibility.check(&cur_module, &new_module) {
            error!("COMPARE_SYSTEM_PACKAGE: Compatibility check failed, for new version of {id}::{name}: {e:?}");
            return None;
        }
        info!("COMPARE_SYSTEM_PACKAGE: Module {id}::{name} is compatible");
    }

    new_pkg.increment_version();
    let final_ref = new_object.compute_object_reference();
    info!(
        "COMPARE_SYSTEM_PACKAGE: Package {} compatibility check passed, new version: {}, final reference: {:?}",
        id, new_object.version(), final_ref
    );
    Some(final_ref)
}
