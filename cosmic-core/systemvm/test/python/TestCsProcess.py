import merge
import unittest
from cs.CsProcess import CsProcess


class TestCsProcess(unittest.TestCase):
    def setUp(self):
        merge.DataBag.DPATH = "."

    def test_init(self):
        csprocess = CsProcess({ })
        self.assertTrue(csprocess is not None)


if __name__ == '__main__':
    unittest.main()
