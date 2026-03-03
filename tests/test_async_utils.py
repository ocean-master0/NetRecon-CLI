import asyncio
import unittest

from netrecon.async_utils import gather_limited, run_async


class AsyncUtilsTests(unittest.TestCase):
    def test_run_async(self):
        async def sample():
            return 5

        self.assertEqual(run_async(sample()), 5)

    def test_gather_limited(self):
        async def runner():
            jobs = [lambda x=i: _job(x) for i in range(3)]
            return await gather_limited(jobs, concurrency=2)

        async def _job(value):
            await asyncio.sleep(0.01)
            return value

        result = run_async(runner())
        self.assertEqual(sorted(result), [0, 1, 2])


if __name__ == "__main__":
    unittest.main()
