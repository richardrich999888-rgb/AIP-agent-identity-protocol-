# VANIAN design review

From the console directory, run `npm ci` and `npm run design:review`. Open `http://127.0.0.1:6006` to review the same React components shipped in the console. The local Storybook MCP endpoint is `http://127.0.0.1:6006/mcp`. The accessibility panel runs axe checks against the selected component.

The sensor stories use deterministic demo heartbeats, a group filter, an empty scope and an explicitly illustrated archive without fleet health. The evidence stories run the retained upstream verifier in a browser Worker against the repository’s lab fixtures. A successful result reveals the signed chain head. The changed-byte case must reject the capture.

## Full-screen review

Run `npm run build`, install Chromium with `npx playwright install chromium`, then run `npm run design:capture`. A Linux host with an existing Chromium installation can set `VANIAN_CHROMIUM` to the executable. This starts an isolated local Worker, applies the sample database schema, and records the application at desktop and phone widths. No external account is needed.

| Desktop workflow | Recorded view |
| --- | --- |
| Fleet coverage and AI activity | [Security overview](../docs/preview/security-overview.png) |
| Filter and investigate a detection | [Alert investigation](../docs/preview/alert-investigation.png) |
| Inspect a node and its relationships | [Agent lineage](../docs/preview/agent-lineage.png) |
| Verify the archived process lifecycle capture | [Evidence verification](../docs/preview/evidence-verification.png) |

[Phone overview](../docs/preview/mobile-overview.png) · [Run the native AIP verification gate](../bridge/IMPLEMENTATION.md)

## Spatial lineage

Run `npm run design:capture -- --spatial` to capture the Three.js view. This requires WebGL2. For Chromium with SwiftShader installed, set `VANIAN_SOFTWARE_WEBGL=1` to use the local software renderer. The command fails if the 2D fallback is displayed.

Each successful console verification job attaches the desktop, phone, evidence and 3D captures as the **vanian-design-review** artifact for 30 days. All dashboard captures use the synthetic tenant. The evidence screenshot shows verification of the retained lab capture.

## Design references

- [WitnessAI Observe](https://witness.ai/observe/) and the supplied tour informed the observation-to-investigation workflow.
- [IBM Carbon data tables](https://carbondesignsystem.com/components/data-table/usage/) informed row density, sorting and toolbar layout.
- [Storybook MCP](https://storybook.js.org/addons/@storybook/addon-mcp) and [accessibility checks](https://storybook.js.org/docs/writing-tests/accessibility-testing) support local component review.
