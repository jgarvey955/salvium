# OpenSSL 4.0.1 security baseline

The release archive remains OpenSSL 4.0.1, as requested. The manifest records
23 official security backports and their source commits. One CMS allocation
fix is adapted to the original 4.0.1 cleanup context; the allocation rule
matches upstream. The combined patch and original archive have exact digests.

QUIC is disabled in every recipe because neither the core nor Qt 5 uses it.
Ten QUIC-only advisories are recorded as excluded by that build configuration,
not claimed as backported. The unnecessary AF_ALG engine and TLS compression
are also disabled. Other platform builds require separate qualification.

The existing installvars patch remains an independent packaging correction.
