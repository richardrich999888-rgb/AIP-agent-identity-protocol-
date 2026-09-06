"""Reference model / inference adapter.

# The chain this adapter sits on top of

::

    Python  →  PyTorch / JAX / TensorFlow  →  XLA / native runtime  →  CUDA

This adapter is authored at the **top** of that chain. Everything below it is
reported to it by the layer directly beneath, and it can verify none of it.
That is not a defect in the adapter; it is where the process boundary is.

# What is observable from here, and what is not

======================================  ==========================================
Layer                                   What this adapter can establish
======================================  ==========================================
Which model the agent *requested*       The request, as a signed self-report
Which model the provider *served*       Nothing. Hosted APIs return an identifier
                                        the caller cannot check.
Which weights were loaded (local)       A digest, **if** something outside this
                                        process computed it. A digest the agent
                                        computes of a file it also controls is a
                                        statement about that file, not about what
                                        the runtime loaded into memory.
Which framework ran                     The framework's own version string
Whether XLA / a native kernel ran       Nothing. Framework telemetry reporting a
                                        kernel launch is still framework telemetry.
Whether a GPU executed anything         Nothing from here. ``accelerator`` is a
                                        self-reported string. Establishing GPU
                                        execution needs a source outside the
                                        process — a device-level exporter, a
                                        driver-level probe, or an attested runtime.
======================================  ==========================================

Where a distinction matters and the evidence does not exist, the honest
answer is ``CANNOT_PROVE``, and the corroboration engine returns exactly that
for model events: ``NotEvaluated(NotExternallyObservable)``. A host observer
sees a socket, and that socket is the *tool* layer's evidence — attributing
it to the model layer would count one fact twice.

# Replay for non-deterministic inference

Replay here means *policy and evidence equivalence*, never bitwise
reproduction of model output. Two runs of the same prompt against the same
model legitimately differ. What must reproduce is the commitment structure:
the same prompt bytes commit to the same digest, and the signed binding
between agent, execution, expectation and model survives re-verification.
"""

from __future__ import annotations

from typing import Any, Optional

from ..commitment import commit_json
from ..emitter import AiriEmitter
from ..events import ModelProvenance

__all__ = ["ModelAdapter", "describe_local_runtime"]


def describe_local_runtime() -> tuple[str, Optional[str]]:
    """Best-effort ``(runtime, version)`` for a locally installed framework.

    Import errors are swallowed deliberately: absence of a framework is not
    an error, and a missing version is recorded as ``None`` rather than
    guessed. Order is arbitrary; the first found wins, and a deployment using
    several should pass ``runtime`` explicitly rather than rely on this.
    """
    for module, name in (
        ("torch", "pytorch"),
        ("jax", "jax"),
        ("tensorflow", "tensorflow"),
        ("vllm", "vllm"),
    ):
        try:
            mod = __import__(module)
        except Exception:  # noqa: BLE001 - any import failure means "not here"
            continue
        return name, getattr(mod, "__version__", None)
    return "hosted-api", None


class ModelAdapter:
    """Emits model provenance without over-claiming what it can see."""

    def __init__(self, emitter: AiriEmitter) -> None:
        self._em = emitter

    def requested(
        self,
        model_id: str,
        *,
        runtime: Optional[str] = None,
        runtime_version: Optional[str] = None,
        prompt: Any = None,
        inference_request_id: Optional[str] = None,
        model_digest: Optional[bytes] = None,
        accelerator: Optional[str] = None,
    ) -> None:
        """Record that the agent asked for ``model_id``.

        :param model_digest: supply only when something **outside this
            process** measured the weights. Passing a digest the agent
            computed itself records a self-measurement as if it were
            provenance, which is exactly the confusion this layer exists to
            prevent. For hosted inference the correct value is ``None``.
        :param accelerator: free-form, self-reported. Recorded for a human
            reading the trace; never evidence that a device ran anything.
        """
        rt, rv = (runtime, runtime_version)
        if rt is None:
            rt, rv = describe_local_runtime()
        self._em.model_requested(
            ModelProvenance(
                model_id=model_id,
                runtime=rt,
                runtime_version=rv,
                model_digest=model_digest,
                inference_request_id=inference_request_id,
                prompt_commitment=None if prompt is None else commit_json(prompt),
                accelerator=accelerator,
            )
        )

    def returned(
        self,
        model_id: str,
        *,
        runtime: Optional[str] = None,
        output: Any = None,
        inference_request_id: Optional[str] = None,
    ) -> None:
        """Record what the framework said came back.

        Emitted as ``MODEL_INVOCATION_OBSERVED``. The word "observed" is the
        specification's; the observer is the framework, in this process. It
        is a self-report and carries no more weight than any other.
        """
        rt = runtime or describe_local_runtime()[0]
        self._em.model_observed(
            ModelProvenance(
                model_id=model_id,
                runtime=rt,
                inference_request_id=inference_request_id,
                output_commitment=None if output is None else commit_json(output),
            )
        )
