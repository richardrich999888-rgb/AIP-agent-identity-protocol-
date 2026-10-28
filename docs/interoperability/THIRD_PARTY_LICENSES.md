# Third-party license findings

These records identify licenses at inspected commits, not legal advice or blanket approval for a future combined distribution. No upstream source/binary/model is vendored by this increment. Preserve upstream license/NOTICE and attribution files when distributing installed dependencies; inspect transitive packages separately.

| Project | License | Source at inspected commit |
|---|---|---|
| a2aproject/A2A | Apache-2.0 | [LICENSE](https://github.com/a2aproject/A2A/blob/89699392a324fb24ac19824041f3bbda131789ad/LICENSE) |
| a2aproject/a2a-python | Apache-2.0 | [LICENSE](https://github.com/a2aproject/a2a-python/blob/43d1eff1b726af7a42874e212683396f62fbcaa3/LICENSE) |
| agntcy/identity | Apache-2.0 | [LICENSE](https://github.com/agntcy/identity/blob/8f7c1b52b5c4585cbd6308053ff43e076d96927e/LICENSE) |
| agntcy/oasf | Apache-2.0 | [LICENSE.md](https://github.com/agntcy/oasf/blob/9f370e8ca1cc0d1b73cb61328198868ead55dbbb/LICENSE.md) |
| agntcy/slim | Apache-2.0 | [LICENSE.md](https://github.com/agntcy/slim/blob/03eb7cce8ae7df2113d8cac2ee3b8eda9f0ab6d4/LICENSE.md) |
| agntcy/dir | Apache-2.0 | [LICENSE.md](https://github.com/agntcy/dir/blob/a46fa138d8d6b713f4816279cba170eb2cde2d40/LICENSE.md) |
| spiffe/spire | Apache-2.0 | [LICENSE](https://github.com/spiffe/spire/blob/a33d43d3c1cd734b6eca0c6ec6582353a5d35eb0/LICENSE) |
| spiffe/go-spiffe | Apache-2.0 | [LICENSE](https://github.com/spiffe/go-spiffe/blob/77c6d2e0c1203e36804e26a02faa8f893d72e7e5/LICENSE) |
| NVIDIA/OpenShell | Apache-2.0 | [LICENSE](https://github.com/NVIDIA/OpenShell/blob/44ef984b58f9badf79f2ff5b9982054017b01ca8/LICENSE) |
| NVIDIA-NeMo/Guardrails | Apache-2.0 | [LICENSE.md](https://github.com/NVIDIA-NeMo/Guardrails/blob/e6b1c2bb1c6072279f9d7566b08e5567d1693ce8/LICENSE.md) |
| NVIDIA/NeMo-Agent-Toolkit | Apache-2.0 | [LICENSE.md](https://github.com/NVIDIA/NeMo-Agent-Toolkit/blob/79e18491fa9fef7677ed9b55d85013cafa95779b/LICENSE.md) |
| google/adk-python | Apache-2.0 | [LICENSE](https://github.com/google/adk-python/blob/34750dcb85f4cdefefe002f8c3f156c471d29b52/LICENSE) |
| microsoft/agent-governance-toolkit | MIT | [LICENSE](https://github.com/microsoft/agent-governance-toolkit/blob/4eca1f5b44d30ebe5e9745ac36ca394f887e617b/LICENSE) |
| open-policy-agent/opa | Apache-2.0 | [LICENSE](https://github.com/open-policy-agent/opa/blob/ca660665cc95b0fce665b71192aac938889719c9/LICENSE) |
| cedar-policy/cedar | Apache-2.0 | [LICENSE](https://github.com/cedar-policy/cedar/blob/710fa6e6a33d93e58845a73861c364c25202037c/LICENSE) |
| openfga/openfga | Apache-2.0 | [LICENSE](https://github.com/openfga/openfga/blob/44054f542f64e9b9589dd26a595081b3d2cfd942/LICENSE) |
| modelcontextprotocol/modelcontextprotocol | Apache-2.0 / MIT transition; docs CC-BY-4.0 | [LICENSE](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/ccaf9102ec5eb656eab50ca8333ef49dcd259c26/LICENSE) |
| IBM/mcp-context-forge | Apache-2.0 | [LICENSE](https://github.com/IBM/mcp-context-forge/blob/cea3b88aa4e34ce2e922e7073f6884c97f3fcb19/LICENSE) |
| open-telemetry/semantic-conventions-genai | Apache-2.0 | [LICENSE](https://github.com/open-telemetry/semantic-conventions-genai/blob/51a0f580f8a6ad804ca4de5e033683c6fbbe5906/LICENSE) |
| CycloneDX/specification | Apache-2.0 | [LICENSE](https://github.com/CycloneDX/specification/blob/ad83dae28b236b8760286399da4daba77592de86/LICENSE) |
| cilium/tetragon | Apache-2.0 | [LICENSE](https://github.com/cilium/tetragon/blob/31fa5abdddab20cd2cf7452f61b63f0fa6758c64/LICENSE) |
| falcosecurity/falco | Apache-2.0 | [LICENSE](https://github.com/falcosecurity/falco/blob/2433beca300b9afc03d90ea2b8a169cf508e045a/LICENSE) |
| linux-audit/audit-userspace | GPL-2.0; library LGPL-2.1 (COPYING.LIB) | [COPYING](https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/COPYING); [COPYING.LIB](https://github.com/linux-audit/audit-userspace/blob/280cb8c07c431439ff85771988b9656780b8ef2b/COPYING.LIB) |
| opena2a-standards/agent-identity-protocol | Apache-2.0 | [LICENSE](https://github.com/opena2a-standards/agent-identity-protocol/blob/8e641ebd3fc2e7eac56641db4a50d1e9ea1a8b40/LICENSE) |
| a2aproject/a2a-tck | Apache-2.0 | [LICENSE](https://github.com/a2aproject/a2a-tck/blob/d4d6fae7887f88ef607fb461c13e3b0e1802f19b/LICENSE) |

Apache-2.0 requires preserving the license and applicable notices, marking modifications and respecting its patent/trademark terms. MIT requires retaining copyright and license notices. MCP is in a contribution-specific MIT→Apache transition; non-spec documentation is CC-BY-4.0, so a single Apache label would be inaccurate.

Linux Audit uses GPL-2.0 for programs and LGPL-2.1 for library material. No audit-userspace code is linked or copied here. A future packaged appliance must separately assess source/notice and linking obligations before redistribution.

Guardrails LICENSE.md explicitly identifies Apache-2.0 despite GitHub metadata returning NOASSERTION. NeMo toolkit includes separate third-party licensing material. CycloneDX schemas are Apache-2.0; that does not make custom VANIAN properties standardized.

The Qwen model revision is Apache-2.0; its LICENSE file digest is in upstreams.lock.json. PyTorch/Transformers and native ACS dependencies are recorded in runtime-packages.json. This inventory does not constitute a completed transitive redistribution audit. Microsoft compatibility code is MIT; agent-control-spec native crate provenance is separately pinned.
