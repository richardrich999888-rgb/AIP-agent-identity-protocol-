# Evaluation installation status

Clean-host P0-057 installation/uninstall acceptance: **NOT RUN**.
This checkpoint is a source/evidence branch, not a newly qualified Linux package.

Reuse existing components:

- [`deploy/enterprise/linux/README.md`](../../deploy/enterprise/linux/README.md): native package/build/staging and Linux setup.
- [`deploy/enterprise/README.md`](../../deploy/enterprise/README.md): evaluation deployment boundaries.
- [`deploy/enterprise/airgap/README.md`](../../deploy/enterprise/airgap/README.md): offline prerequisites and their limits.
- [`integrations/service_delivery`](../../integrations/service_delivery): deployment registry/enrollment and onboarding.
- [`deploy/enterprise/runbooks/OPERATIONS.md`](../../deploy/enterprise/runbooks/OPERATIONS.md): health, recovery and retained-data cleanup.

Do not assemble branches manually or apply the opt-in Kubernetes template as a
qualified deployment. First build a single immutable candidate containing reviewed
dependencies, validate its configuration/default denial, enroll collector/workload,
provision public AIP anchors separately, start sensors, ingest evidence and verify
it offline. Test the existing read-only console/coverage output against that exact
deployment. Consequential production enforcement remains disabled.

On clean supported authorised Linux hosts, test install, restart, collector loss,
recovery and uninstall. Retain public evidence and existing keys/data under the
operator's retention policy; do not delete them as an uninstall shortcut. Record
actual package hashes, service privileges, commands and return codes. Fixture ELF
packaging tests and a source build cannot be substituted for this lifecycle.

The restricted local workspace was used only for builds/tests and ephemeral
synthetic children. No system service or production sensor was installed.
