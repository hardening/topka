import unittest
from topka.utils import expandVariables

class Test(unittest.TestCase):

    def testExpandVariables(self):
        context = {'auth:toto': 'totoV'}
        self.assertEqual(expandVariables("value={auth:toto} unknown={unknown}", context), "value=totoV unknown=")


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()