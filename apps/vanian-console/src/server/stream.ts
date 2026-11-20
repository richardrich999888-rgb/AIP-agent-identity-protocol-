import { live } from "./live";
/** Publish changes in completed, reverified archive projections. The reader never asserts sensor connectivity. */
export async function observationStream(
  req: Request,
  params: URLSearchParams,
  env: Cloudflare.Env,
) {
  const first = await live(req, "snifferdog/events", params, env);
  let timer: ReturnType<typeof setTimeout> | undefined,
    stopped = false;
  const enc = new TextEncoder();
  let previous = "";
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      const finish = () => {
        if (stopped) return;
        stopped = true;
        if (timer) clearTimeout(timer);
        req.signal.removeEventListener("abort", finish);
        try {
          controller.close();
        } catch {}
      };
      req.signal.addEventListener("abort", finish, { once: true });
      const emit = (d: typeof first) => {
        const revision = JSON.stringify([
          d.meta.asOf,
          d.rows.map((x) => [x.id, x.at, x.fields.archiveSha256]),
        ]);
        if (revision === previous) {
          controller.enqueue(enc.encode(": verified archive unchanged\n\n"));
          return;
        }
        previous = revision;
        controller.enqueue(
          enc.encode(
            "event: snapshot\ndata: " +
              JSON.stringify({
                asOf: d.meta.asOf,
                processedAt: d.meta.processedAt,
                status: d.meta.status,
                records: d.rows.map((r) => r.id),
              }) +
              "\n\n",
          ),
        );
      };
      emit(first);
      let remaining = 11;
      const tick = async () => {
        if (stopped) return;
        try {
          const next = await live(req, "snifferdog/events", params, env);
          if (stopped) return;
          emit(next);
          if (--remaining > 0) timer = setTimeout(tick, 5000);
          else finish();
        } catch {
          if (!stopped)
            controller.enqueue(
              enc.encode(
                'event: unavailable\ndata: {"status":"Source unavailable"}\n\n',
              ),
            );
          finish();
        }
      };
      timer = setTimeout(tick, 5000);
    },
    cancel() {
      stopped = true;
      if (timer) clearTimeout(timer);
    },
  });
  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "private, no-store, no-transform",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
