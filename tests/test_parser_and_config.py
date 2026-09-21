import os
import tempfile
import unittest

import scapy.all as scapy

from core.parser import get_packet_metadata
from utils.config import default_config, load_config, save_config


class ParserAndConfigTests(unittest.TestCase):
    def test_ipv6_metadata_is_detected(self):
        packet = scapy.Ether() / scapy.IPv6(src="2001::1", dst="2001::2") / scapy.ICMPv6EchoRequest()

        metadata = get_packet_metadata(packet)

        self.assertEqual(metadata["protocol"], "ICMPv6")
        self.assertEqual(metadata["src"], "2001::1")
        self.assertEqual(metadata["dst"], "2001::2")

    def test_config_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.json")
            config = default_config()
            config["max_packets"] = 1234

            save_config(config_path, config)
            loaded = load_config(config_path)

            self.assertEqual(loaded["max_packets"], 1234)


if __name__ == "__main__":
    unittest.main()
