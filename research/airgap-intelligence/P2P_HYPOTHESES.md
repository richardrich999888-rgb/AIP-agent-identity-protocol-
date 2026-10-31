# P2P hypotheses — four different problems

Nothing in this file is built. Each hypothesis states what would reject it.

## A. Model distribution (BitTorrent-like chunk exchange)

- **What is borrowed:** content-addressed chunks, a signed manifest of chunk
  hashes (like a .torrent's piece hashes / a Merkle root), peers serving chunks
  they already verified, resumable transfer.
- **Benefit if true:** less load on one internal server when many machines
  update at once.
- **Existing alternatives:** an internal HTTP artifact server with a CDN-style
  cache; rsync/zsync; OCI registries with pull-through cache; IPFS-style CAS;
  multicast imaging tools.
- **Reject if:** on the customer's LAN, a single server saturates no link and
  finishes the fleet update within the maintenance window, or peer traffic
  crosses network segments the security team will not allow.
- **Note:** the security property (verify every chunk against a signed
  manifest) is independent of P2P and should be built regardless.

## B. Task distribution (send work to suitable approved machines)

- **What is borrowed:** a scheduler aware of capability (CPU/GPU/RAM, loaded
  models) and permission (which data each node may hold).
- **Reject if:** one adequately sized server meets latency/throughput at lower
  total ownership cost, or the scheduler's data movement creates new
  disclosure paths.

## C. Model partitioning (one model across many machines)

- **Prior art:** Petals; pipeline/tensor parallelism (Megatron, DeepSpeed);
  llama.cpp RPC backend.
- **First-principles cost:** per generated token, activations cross the
  network once per partition boundary; on 1 Gb/s LAN with ms-scale latency,
  autoregressive decoding pays that latency per token. A quantized model on one
  GPU server avoids it entirely.
- **Reject if** (expected): tokens/s across commodity workstations is below a
  single quantized-model server the customer could buy for the same money.

## D. Knowledge locality (compute where the data lives)

- **Idea:** run retrieval/extraction on the node that holds the classified
  data; return only policy-approved typed results.
- **Caution:** embeddings, activations and summaries can leak the source; they
  are data under the same classification unless shown otherwise.
- **Reject if:** returned intermediate results require the same clearance as
  the raw documents (then nothing is gained over a central authorised store).

## Order

A and the signed-manifest part first (cheap, measurable, security value even
without P2P). B only after a single-node product exists. C expected to be
rejected for target customers. D is a research question about leakage before
it is an engineering one.
