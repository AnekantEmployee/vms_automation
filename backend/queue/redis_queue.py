import asyncio
import json
from collections import defaultdict

# In-memory queues — dict of job_id -> asyncio.Queue
_queues: dict[str, asyncio.Queue] = defaultdict(asyncio.Queue)


async def push_result(job_id: str, data: dict):
    await _queues[job_id].put(json.dumps(data))


async def pop_result(job_id: str):
    try:
        value = await asyncio.wait_for(_queues[job_id].get(), timeout=5)
        return json.loads(value)
    except asyncio.TimeoutError:
        return None


async def clear_queue(job_id: str):
    _queues.pop(job_id, None)
