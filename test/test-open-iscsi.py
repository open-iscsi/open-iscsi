#!/usr/bin/env python3
"""
Unit tests for open-iscsi, using the unittest built-in package
"""

import sys
import unittest
import os
import time
from harness import util
#from harness import tests
#from tests import TestRegression

__version__ = '1.0'


if __name__ == '__main__':
    # do our own hackery first, to get access to verbosity, debug, etc,
    # as well as add our own command-line options
    util.setup_testProgram_overrides(__version__, 'test-open-iscsi.py')
    # now run the tests
    unittest.main(module = 'harness.tests')
