import unittest
from docopt import docopt
from pyraider import cli

doc = cli.__doc__

class TestCLI(unittest.TestCase):
    def test_go(self):
        args = docopt(doc,["go"])
        self.assertEqual(args["go"], True)
    
    def test_validate(self):
        args = docopt(doc,["validate"])
        self.assertEqual(args["validate"], True)
        
    def test_fix(self):
        args = docopt(doc,["fix"])
        self.assertEqual(args["fix"], True)
    
    def test_autofix(self):
        args = docopt(doc,["autofix"])
        self.assertEqual(args["autofix"], True)
    

if __name__ == '__main__':
    unittest.main()