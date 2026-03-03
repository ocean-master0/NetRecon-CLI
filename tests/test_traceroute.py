import asyncio
import unittest

from netrecon.traceroute import TracerouteScanner


class TracerouteTests(unittest.TestCase):
    def test_parse_output(self):
        scanner = TracerouteScanner()
        sample = """
 1  192.168.1.1  1.123 ms  1.011 ms  1.009 ms
 2  10.0.0.1     5.1 ms    4.9 ms    5.0 ms
 3  142.250.183.78 18.0 ms 17.9 ms 18.1 ms
"""
        hops = scanner._parse_traceroute_output(sample)
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[0].ip, "192.168.1.1")
        self.assertEqual(hops[2].hop, 3)

    def test_trace_async_enrichment(self):
        async def enrich(ip):
            return "AS15169", "Mountain View, US"

        scanner = TracerouteScanner(enrich_hop=enrich)
        result = asyncio.run(scanner.trace_async("127.0.0.1", advanced=True))
        self.assertEqual(result.target, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
