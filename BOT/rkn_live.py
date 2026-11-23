from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import shutil
import time
from collections.abc import AsyncIterator
from typing import Any

from .shell import LocalShell

CURSOR = re.compile(r"[A-Za-z0-9;=]{1,1024}")


def event_line(event: Any, kind: str) -> str:
    if not isinstance(event, dict):
        return ""
    message = event.get("MESSAGE", "")
    if not isinstance(message, str) or "OBHOD-RKN-%s:" % kind not in message:
        return ""
    try:
        stamp = int(event.get("__REALTIME_TIMESTAMP", "0")) / 1000000
        date = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(stamp)) if stamp > 0 else ""
    except (ValueError, OverflowError, TypeError):
        date = ""
    return ((date + " ") if date else "") + message.replace("\n", " ")[:2000]


async def journal_stream(shell: LocalShell, kind: str, cursor: str = "", started_at: int = 0) -> AsyncIterator[str]:
    if kind not in ("v4", "v6") or (cursor and not CURSOR.fullmatch(cursor)):
        raise ValueError("invalid live journal selector")
    tool = shutil.which("journalctl")
    if not tool:
        raise RuntimeError("journalctl is not installed")
    if shell.escalated:
        raise RuntimeError("live journal stream requires a root bot process")
    since = max(0, min(int(started_at or 0), int(time.time())))
    selector = "--after-cursor=" + cursor if cursor else ("--since=@%d" % since if since else "--since=-1 minute")
    command = [tool, "-k", "--follow", "--no-tail", "--no-pager", "--quiet", "-o", "json", "--grep=OBHOD-RKN-" + kind + ":", selector]
    process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, limit=65536, start_new_session=True)
    errors = bytearray()

    async def drain_errors() -> None:
        while True:
            block = await process.stderr.read(4096)
            if not block:
                return
            errors.extend(block[:max(0, 2048 - len(errors))])

    stderr_task = asyncio.create_task(drain_errors())
    try:
        while True:
            data = await process.stdout.readline()
            if not data:
                await process.wait()
                await stderr_task
                detail = errors.decode("utf-8", "replace").strip()[:160]
                raise RuntimeError(detail or "journal stream stopped")
            try:
                item = json.loads(data)
            except (ValueError, UnicodeDecodeError):
                raise RuntimeError("invalid journal stream event") from None
            line = event_line(item, kind)
            if line:
                yield line
    finally:
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), 2)
            except asyncio.TimeoutError:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()
        if not stderr_task.done():
            stderr_task.cancel()
        await asyncio.gather(stderr_task, return_exceptions=True)
