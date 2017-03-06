import unittest

class cloudstackTestCase(unittest.case.TestCase):

    @classmethod
    def getClsTestClient(cls):
        return cls.clstestclient

    @classmethod
    def getClsConfig(cls):
        return cls.config

    def setup_infra(self):
        print self
