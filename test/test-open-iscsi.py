#!/usr/bin/env python3
"""
Unit tests for open-iscsi, using the unittest built-in package
"""

import sys
import unittest
import os
import time
from harness import util
from harness.util import Global
from harness.iscsi import IscsiData


class TestRegression(unittest.TestCase):
    """
    Regression testing
    """

    @classmethod
    def setUpClass(cls):
        util.verify_needed_commands_exist(['parted', 'fio', 'mkfs', 'bonnie++', 'dd', 'iscsiadm'])
        util.vprint('*** Starting %s' % cls.__name__)
        # XXX validate that target exists?
        # an array of first burts, max burst, and max recv values, for testing
        cls.param_values = [[4096, 4096, 4096],
                            [8192, 4096, 4096],
                            [16384, 4096, 4096],
                            [32768, 4096, 4096],
                            [65536, 4096, 4096],
                            [131972, 4096, 4096],
                            [4096, 8192, 4096],
                            [4096, 16384, 4096],
                            [4096, 32768, 4096],
                            [4096, 65536, 4096],
                            [4096, 131072, 4096],
                            [4096, 4096, 8192],
                            [4096, 4096, 16384],
                            [4096, 4096, 32768],
                            [4096, 4096, 65536],
                            [4096, 4096, 131072]]

    def setUp(self):
        if Global.debug or Global.verbosity > 1:
            # this makes debug printing a little more clean
            print('', file=sys.stderr)

    def iscsi_logout(self):
        res = util.run_cmd(['iscsiadm', '-m', 'node',
                            '-T', Global.target,
                            '-p', Global.ipnr,
                            '--logout'])
        if res not in [0, 21]:
            self.fail('logout failed')
        self.assertFalse(os.path.exists(Global.device), '%s: exists after logout!' % Global.device)

    def test_InitialR2T(self):
        """Test Initial Request to Transmit set, but no Immediate Data"""
        i = 1
        for v in self.param_values:
            with self.subTest('Testing FirstBurst={} MaxBurts={} MaxRecv={}'.format(*v), i=i):
                self.iscsi_logout()
                iscsi_data = IscsiData('No', 'Yes', 'None', 'None', v[0], v[1], v[2])
                iscsi_data.update_cfg(Global.target, Global.ipnr)
                self.run_the_rest()
            i += 1

    def test_ImmediateData(self):
        """Test Initial Request to Transmit set, but no Immediate Data"""
        i = 1
        for v in self.param_values:
            with self.subTest('Testing FirstBurst={} MaxBurts={} MaxRecv={}'.format(*v), i=i):
                self.iscsi_logout()
                iscsi_data = IscsiData('Yes', 'No', 'None', 'None', v[0], v[1], v[2])
                iscsi_data.update_cfg(Global.target, Global.ipnr)
                self.run_the_rest()
            i += 1

    def run_the_rest(self):
        res = util.run_cmd(['iscsiadm', '-m', 'node',
                            '-T', Global.target,
                            '-p', Global.ipnr,
                            '--login'])
        self.assertEqual(res, 0, 'cannot login to device')
        # wait a few seconds for the device to show up
        if not util.wait_for_path(Global.device):
            self.fail('%s: does not exist after login' % Global.device)
        (res, reason) = util.run_fio()
        self.assertEqual(res, 0, reason)
        (res, reason) = util.run_parted()
        self.assertEqual(res, 0, reason)
        (res, reason) = util.run_mkfs()
        self.assertEqual(res, 0, reason)
        (res, reason) = util.run_bonnie()
        self.assertEqual(res, 0, reason)

    @classmethod
    def tearDownClass(cls):
        # restore iscsi config
        iscsi_data = IscsiData()
        iscsi_data.update_cfg(Global.target, Global.ipnr)
        # log out of iscsi connection
        util.run_cmd(['iscsiadm', '-m', 'node',
                      '-T', Global.target,
                      '-p', Global.ipnr,
                      '--logout'])


if __name__ == '__main__':
    # do our own hackery first, to get access to verbosity, debug, etc,
    # as well as add our own command-line options
    util.setup_testProgram_overrides()
    # now run the tests
    unittest.main()
