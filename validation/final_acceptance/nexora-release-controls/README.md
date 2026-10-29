# NEXORA release fixture correction

The exact42d0d96 full Linux release run reported11 passing and1 failing test in `aip-nexora --test binding`. The failed third assertion in b05 assumed two separately signed fixture health records had different millisecond reference timestamps. Optimized construction could put both at the same observer/sequence/timestamp coordinates. The structural comparison deliberately does not verify signatures; complete anchored verification does.

The test now asks B's real signer for a health record at `max(A.at, B.at)+1`, making the uncited reference deterministic without sleeping or changing production verification. A separate regression preserves the same health coordinates and changes only the signing key; anchored verification refuses that record and cannot return `Valid`.

The focused locked release binding/verifier suites passed12+15 tests. Twenty repeated complete release binding runs passed12 tests each (240 test executions), as retained in the repetition directory. These repeated executions are not 240 distinct security properties.

The first publication contained an unnecessary `mut`, correctly rejected by CI's warning-denying build. Removing it is recorded separately; strict locked all-feature Clippy for the two affected test targets then passed (`nexora-clippy-strict.log`). Full supported-Linux CI must qualify the corrected source, as recorded by its exact-source receipts. No cryptographic format, trust rule or production code was altered for this fixture repair.
