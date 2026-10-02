//! Server-owned durable share policy authority. Runtime adapters must retain a
//! read lease for the complete operation, rather than caching policy at startup.
use crate::{Error, Lease, Policy, Result, atomic_json, bounded_read, digest, lock, now};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

const MAX_CHANGES: usize = 1024;
const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

/// An administrative policy event committed in the same document as its policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyChange {
    /// Monotonic share policy revision, independent of overlay generations.
    pub revision: u64,
    /// Server-verified administrative actor, never a client ownership assertion.
    pub actor: String,
    /// Commit time in Unix seconds.
    pub committed_at: u64,
    /// Digest of the superseded policy; contains no user content or host paths.
    pub previous_digest: String,
    /// Digest of the committed policy.
    pub policy_digest: String,
}

/// Last explicitly acknowledged archive, anchoring the remaining event chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCheckpoint {
    pub revision: u64,
    pub actor: String,
    pub acknowledged_at: u64,
    pub policy_digest: String,
    pub batch_digest: String,
    pub previous_checkpoint_digest: Option<String>,
}

/// Portable bounded audit batch. Its canonical JSON digest is the audit ETag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuditBatch {
    pub schema: u32,
    pub organization: String,
    pub share: String,
    pub revision: u64,
    pub policy_digest: String,
    pub checkpoint: Option<PolicyCheckpoint>,
    pub changes: Vec<PolicyChange>,
}
impl PolicyAuditBatch {
    pub fn fingerprint(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }
}

/// Versioned authority for one organisation/share. No upper data is stored here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// Durable format version.
    pub schema: u32,
    /// Server-configured organisation.
    pub organization: String,
    /// Server-configured share.
    pub share: String,
    /// Monotonic revision, including changes back to an earlier policy.
    pub revision: u64,
    /// Effective policy. Existing retained-object expiries are not rewritten.
    pub policy: Policy,
    /// Durable administrative outbox. A full outbox rejects further changes.
    pub changes: Vec<PolicyChange>,
    /// Absent in schema 1. Schema 2 requires an explicit archive acknowledgement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<PolicyCheckpoint>,
}

/// A consistent policy document protected against concurrent replacement.
#[derive(Debug)]
pub struct PolicyRead {
    document: PolicyDocument,
    _lease: Lease,
}
impl PolicyRead {
    /// Borrow the policy while retaining its cross-process read lease.
    pub fn document(&self) -> &PolicyDocument {
        &self.document
    }

    pub fn audit_batch(&self) -> Result<PolicyAuditBatch> {
        batch(&self.document)
    }

    /// Bind previews to scope, policy values and monotonic revision, preventing ABA.
    pub fn fingerprint(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(&(
            &self.document.organization,
            &self.document.share,
            self.document.revision,
            &self.document.policy,
        ))?))
    }
}

/// A catalogue selected only by trusted server configuration. The root must be
/// an existing absolute directory; API requests never supply this host path.
#[derive(Debug, Clone)]
pub struct SharePolicyCatalog {
    document_path: PathBuf,
    lock_path: PathBuf,
    organization: String,
    share: String,
}
impl SharePolicyCatalog {
    /// Initialise exactly once, or reopen the durable policy without overriding
    /// it with startup defaults. Bootstrap and replacement share the same lock.
    pub fn open(root: &Path, organization: &str, share: &str, initial: Policy) -> Result<Self> {
        initial.validate()?;
        if !root.is_absolute() || !valid_identity(organization) || !valid_identity(share) {
            return Err(Error::Path);
        }
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::Path);
        }
        let root = fs::canonicalize(root)?;
        let identity = digest(&serde_json::to_vec(&(organization, share))?);
        let catalog = Self {
            document_path: root.join(format!("{identity}.policy.json")),
            lock_path: root.join(format!("{identity}.policy.lock")),
            organization: organization.into(),
            share: share.into(),
        };
        let _lease = catalog.exclusive(false)?;
        match fs::symlink_metadata(&catalog.document_path) {
            Ok(_) => {
                catalog.load()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                atomic_json(
                    &catalog.document_path,
                    &PolicyDocument {
                        schema: 1,
                        organization: organization.into(),
                        share: share.into(),
                        revision: 0,
                        policy: initial,
                        changes: Vec::new(),
                        checkpoint: None,
                    },
                )?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(catalog)
    }

    /// Hold a shared cross-process lease across an entire storage operation.
    pub fn read(&self) -> Result<PolicyRead> {
        self.validate_lock()?;
        let lease = lock(&self.lock_path, false, false)?;
        Ok(PolicyRead {
            document: self.load()?,
            _lease: lease,
        })
    }

    /// Atomically replace policy and append its audit event. A stale revision,
    /// active read lease or full audit outbox leaves the prior document intact.
    /// This primitive is not authorization; callers must authorize separately.
    pub fn replace(&self, expected: u64, actor: &str, policy: Policy) -> Result<PolicyDocument> {
        policy.validate()?;
        if !valid_actor(actor) {
            return Err(Error::Path);
        }
        let _lease = self.exclusive(true)?;
        let mut document = self.load()?;
        if document.revision != expected {
            return Err(Error::Revision);
        }
        if document.changes.len() >= MAX_CHANGES {
            return Err(Error::Quota);
        }
        let revision = document.revision.checked_add(1).ok_or(Error::Quota)?;
        let previous_digest = policy_digest(&document.policy)?;
        let policy_digest = policy_digest(&policy)?;
        document.changes.push(PolicyChange {
            revision,
            actor: actor.into(),
            committed_at: now(),
            previous_digest,
            policy_digest,
        });
        document.revision = revision;
        document.policy = policy;
        atomic_json(&self.document_path, &document)?;
        Ok(document)
    }

    /// Release only the exact exported batch after explicit external archival
    /// acknowledgement. Policy values/revision and storage data are untouched.
    pub fn acknowledge(
        &self,
        expected_digest: &str,
        through_revision: u64,
        actor: &str,
    ) -> Result<PolicyDocument> {
        if !valid_digest(expected_digest) || !valid_actor(actor) {
            return Err(Error::Path);
        }
        let _lease = self.exclusive(true)?;
        let mut document = self.load()?;
        if document.revision != through_revision
            || batch(&document)?.fingerprint()? != expected_digest
        {
            return Err(Error::Revision);
        }
        if document.changes.is_empty() {
            return Err(Error::Path);
        }
        let previous_checkpoint_digest = document
            .checkpoint
            .as_ref()
            .map(|checkpoint| serde_json::to_vec(checkpoint).map(|bytes| digest(&bytes)))
            .transpose()?;
        document.checkpoint = Some(PolicyCheckpoint {
            revision: document.revision,
            actor: actor.into(),
            acknowledged_at: now(),
            policy_digest: policy_digest(&document.policy)?,
            batch_digest: expected_digest.into(),
            previous_checkpoint_digest,
        });
        document.schema = 2;
        document.changes.clear();
        atomic_json(&self.document_path, &document)?;
        Ok(document)
    }

    fn exclusive(&self, nonblocking: bool) -> Result<Lease> {
        self.validate_lock()?;
        lock(&self.lock_path, true, nonblocking)
    }
    fn validate_lock(&self) -> Result<()> {
        match fs::symlink_metadata(&self.lock_path) {
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                Err(Error::Path)
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    fn load(&self) -> Result<PolicyDocument> {
        let document: PolicyDocument =
            serde_json::from_slice(&bounded_read(&self.document_path, MAX_DOCUMENT_BYTES)?)?;
        if !matches!(document.schema, 1 | 2)
            || document.organization != self.organization
            || document.share != self.share
            || document.changes.len() > MAX_CHANGES
        {
            return Err(Error::Corrupt);
        }
        document.policy.validate().map_err(|_| Error::Corrupt)?;
        let anchor = match (document.schema, &document.checkpoint) {
            (1, None) => 0,
            (2, Some(checkpoint))
                if checkpoint.revision > 0
                    && valid_actor(&checkpoint.actor)
                    && valid_digest(&checkpoint.policy_digest)
                    && valid_digest(&checkpoint.batch_digest)
                    && checkpoint
                        .previous_checkpoint_digest
                        .as_ref()
                        .is_none_or(|value| valid_digest(value)) =>
            {
                checkpoint.revision
            }
            _ => return Err(Error::Corrupt),
        };
        if anchor.checked_add(document.changes.len() as u64) != Some(document.revision) {
            return Err(Error::Corrupt);
        }
        let mut previous = document
            .checkpoint
            .as_ref()
            .map(|checkpoint| &checkpoint.policy_digest);
        for (index, change) in document.changes.iter().enumerate() {
            if change.revision != anchor + index as u64 + 1
                || !valid_actor(&change.actor)
                || !valid_digest(&change.previous_digest)
                || !valid_digest(&change.policy_digest)
                || previous.is_some_and(|digest| digest != &change.previous_digest)
            {
                return Err(Error::Corrupt);
            }
            previous = Some(&change.policy_digest);
        }
        let current_digest = policy_digest(&document.policy)?;
        if previous.is_some_and(|digest| digest != &current_digest) {
            return Err(Error::Corrupt);
        }
        Ok(document)
    }
}
fn batch(document: &PolicyDocument) -> Result<PolicyAuditBatch> {
    Ok(PolicyAuditBatch {
        schema: 1,
        organization: document.organization.clone(),
        share: document.share.clone(),
        revision: document.revision,
        policy_digest: policy_digest(&document.policy)?,
        checkpoint: document.checkpoint.clone(),
        changes: document.changes.clone(),
    })
}
fn policy_digest(policy: &Policy) -> Result<String> {
    Ok(digest(&serde_json::to_vec(policy)?))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn valid_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn valid_actor(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}
