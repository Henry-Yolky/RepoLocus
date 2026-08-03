"""Security and privacy boundaries used across RepoLocus."""

from .display import escape_untrusted_display, has_unsafe_display_controls
from .network import is_loopback_url
from .paths import PathSecurityError, ensure_within_root, is_within_root, resolve_within_root
from .privacy import (
    CloudSendPreview,
    ConsentRequiredError,
    PrivacyStore,
    PrivacyStoreError,
    build_cloud_send_preview,
    is_local_provider,
    provider_family,
    require_provider_consent,
)
from .redaction import (
    contains_likely_secret,
    redact_secrets,
    redact_secrets_with_count,
    redact_text,
)

__all__ = [
    "CloudSendPreview",
    "ConsentRequiredError",
    "PathSecurityError",
    "PrivacyStore",
    "PrivacyStoreError",
    "build_cloud_send_preview",
    "contains_likely_secret",
    "ensure_within_root",
    "escape_untrusted_display",
    "has_unsafe_display_controls",
    "is_local_provider",
    "is_loopback_url",
    "is_within_root",
    "provider_family",
    "redact_secrets",
    "redact_secrets_with_count",
    "redact_text",
    "require_provider_consent",
    "resolve_within_root",
]
