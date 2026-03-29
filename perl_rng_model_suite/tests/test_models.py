import unittest
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from perl_rng_models import drand48_key, msvcrt_rand_key, load_keyfile

KEYFILE = ROOT / 'examples' / 'sample_keys.txt'

class ModelRegression(unittest.TestCase):
    def test_load_keyfile(self):
        ids, keys, pos = load_keyfile(KEYFILE)
        self.assertEqual(ids[0], 1)
        self.assertEqual(len(keys), 4)
        self.assertEqual(pos[keys[0]], [0])

    def test_drand48_known_hits(self):
        self.assertEqual(drand48_key(1634202772).hex(), 'da8a5fbf54e106c2813b')
        self.assertEqual(drand48_key(1471041271).hex(), '19cdfbc3255cebc0a94e')
        self.assertEqual(drand48_key(3766097382).hex(), '1384efc1556c602589de')

    def test_msvcrt_differs_on_same_seeds(self):
        self.assertNotEqual(msvcrt_rand_key(1634202772).hex(), 'da8a5fbf54e106c2813b')
        self.assertNotEqual(msvcrt_rand_key(1471041271).hex(), '19cdfbc3255cebc0a94e')

if __name__ == '__main__':
    unittest.main()
