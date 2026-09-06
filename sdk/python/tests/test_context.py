"""Execution context across Python's four concurrency edges.

A context that leaks between concurrent runs files events under the wrong
execution. That is misattribution, and misattribution is the failure this
whole system exists to prevent — so these tests check isolation as carefully
as they check propagation.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import pathlib
import subprocess
import sys
import threading
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from vanian_airi import (  # noqa: E402
    ContextMalformed,
    ContextUnavailable,
    ExecutionContext,
    bind,
    child_execution,
    current,
    current_or_none,
    from_env,
    new_execution,
)

AGENT = "aip1abc"


class TestBasics(unittest.TestCase):
    def test_no_context_is_an_error_not_a_default(self) -> None:
        self.assertIsNone(current_or_none())
        with self.assertRaises(ContextUnavailable):
            current()

    def test_bind_restores_the_previous_context_on_exit(self) -> None:
        outer = new_execution(AGENT)
        inner = new_execution(AGENT)
        with bind(outer):
            self.assertEqual(current().execution_id, outer.execution_id)
            with bind(inner):
                self.assertEqual(current().execution_id, inner.execution_id)
            self.assertEqual(current().execution_id, outer.execution_id)
        self.assertIsNone(current_or_none())

    def test_bind_restores_even_when_the_block_raises(self) -> None:
        ctx = new_execution(AGENT)
        with self.assertRaises(RuntimeError):
            with bind(ctx):
                raise RuntimeError("boom")
        self.assertIsNone(current_or_none())

    def test_execution_ids_are_unpredictable(self) -> None:
        # A predictable execution id lets an attacker pre-compute events for a
        # run that has not started yet.
        ids = {new_execution(AGENT).execution_id for _ in range(200)}
        self.assertEqual(len(ids), 200)

    def test_malformed_identifiers_are_refused(self) -> None:
        with self.assertRaises(ContextMalformed):
            ExecutionContext(agent_id=AGENT, execution_id=b"short")
        with self.assertRaises(ContextMalformed):
            ExecutionContext(agent_id="", execution_id=bytes(16))


class TestAsyncPropagation(unittest.TestCase):
    def test_context_crosses_await_and_is_isolated_between_tasks(self) -> None:
        async def leaf() -> bytes:
            await asyncio.sleep(0)
            return current().execution_id

        async def run_one(ctx: ExecutionContext) -> bytes:
            with bind(ctx):
                return await leaf()

        async def main() -> tuple[bytes, ...]:
            ctxs = [new_execution(AGENT) for _ in range(8)]
            got = await asyncio.gather(*(run_one(c) for c in ctxs))
            # Each task must see its own context, not whichever ran last.
            self.assertEqual(list(got), [c.execution_id for c in ctxs])
            return tuple(got)

        out = asyncio.run(main())
        self.assertEqual(len(set(out)), 8)

    def test_a_task_started_inside_a_binding_inherits_it(self) -> None:
        async def main() -> None:
            ctx = new_execution(AGENT)
            with bind(ctx):
                # contextvars copies into the task at creation time.
                task = asyncio.create_task(asyncio.sleep(0))
                await task
                self.assertEqual(current().execution_id, ctx.execution_id)

        asyncio.run(main())


class TestThreadPropagation(unittest.TestCase):
    def test_a_thread_does_not_inherit_and_must_bind_explicitly(self) -> None:
        # contextvars does not cross a thread boundary. The SDK does not paper
        # over that: a worker must be handed a context deliberately, because a
        # handoff is a lineage event that should be written down.
        parent = new_execution(AGENT)
        seen: dict[str, object] = {}

        def worker_without_bind() -> None:
            seen["implicit"] = current_or_none()

        def worker_with_bind(ctx: ExecutionContext) -> None:
            with bind(ctx):
                seen["explicit"] = current().execution_id

        with bind(parent):
            t1 = threading.Thread(target=worker_without_bind)
            t1.start()
            t1.join()
            child = child_execution(parent)
            t2 = threading.Thread(target=worker_with_bind, args=(child,))
            t2.start()
            t2.join()

        self.assertIsNone(seen["implicit"], "a thread silently inherited a context")
        self.assertEqual(seen["explicit"], child.execution_id)

    def test_concurrent_workers_do_not_cross_contaminate(self) -> None:
        parent = new_execution(AGENT)
        children = [child_execution(parent) for _ in range(16)]

        def work(ctx: ExecutionContext) -> bytes:
            with bind(ctx):
                return current().execution_id

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            got = list(pool.map(work, children))
        self.assertEqual(got, [c.execution_id for c in children])


class TestLineage(unittest.TestCase):
    def test_a_child_names_its_parent_and_inherits_no_extra_authority(self) -> None:
        parent = new_execution(AGENT, decision_id=bytes([0xD1] * 16))
        child = child_execution(parent)
        self.assertEqual(child.parent_execution_id, parent.execution_id)
        self.assertNotEqual(child.execution_id, parent.execution_id)
        # Same decision, never a wider one: being spawned confers nothing.
        self.assertEqual(child.decision_id, parent.decision_id)
        self.assertEqual(child.agent_id, parent.agent_id)


class TestProcessPropagation(unittest.TestCase):
    def test_round_trip_through_the_environment(self) -> None:
        ctx = new_execution(AGENT, decision_id=bytes([0xD1] * 16))
        child = child_execution(ctx)
        env = child.to_env()
        restored = from_env(env)
        self.assertEqual(restored, child)

    def test_absent_context_in_a_child_is_an_error(self) -> None:
        with self.assertRaises(ContextUnavailable):
            from_env({})

    def test_a_malformed_context_is_refused_not_repaired(self) -> None:
        for bad in [
            "v1:agent:nothex:-:-",
            "v2:agent:" + "aa" * 16 + ":-:-",
            "v1:agent:" + "aa" * 8 + ":-:-",  # 8 bytes, not 16
            "garbage",
            "v1:agent:" + "aa" * 16 + ":-",  # too few fields
        ]:
            with self.assertRaises(ContextMalformed, msg=f"accepted {bad!r}"):
                from_env({"VANIAN_AIRI_CONTEXT": bad})

    def test_the_environment_never_carries_key_material(self) -> None:
        ctx = new_execution(AGENT, decision_id=bytes([0xD1] * 16))
        env = ctx.to_env()
        blob = "".join(env.values()).lower()
        for forbidden in ("key", "seed", "secret", "private"):
            self.assertNotIn(forbidden, blob)

    def test_a_real_subprocess_restores_the_context(self) -> None:
        parent = new_execution(AGENT, decision_id=bytes([0xD1] * 16))
        child = child_execution(parent)
        sdk_root = str(pathlib.Path(__file__).resolve().parents[1])
        code = (
            "import sys; sys.path.insert(0, %r)\n"
            "from vanian_airi import from_env\n"
            "c = from_env()\n"
            "print(c.execution_id.hex()); print(c.parent_execution_id.hex())\n"
            % sdk_root
        )
        env = dict(os.environ)
        env.update(child.to_env())
        out = subprocess.run(
            [sys.executable, "-c", code],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        lines = out.stdout.split()
        self.assertEqual(lines[0], child.execution_id.hex())
        self.assertEqual(lines[1], parent.execution_id.hex())


if __name__ == "__main__":
    unittest.main(verbosity=2)
