#!/usr/bin/env python3
"""
Unit tests for open-iscsi, using the unittest built-in package
"""

import sys
import unittest
import os
from harness import util
from harness.util import Global
from harness.iscsi import IscsiData


class TestRegression(unittest.TestCase):
    """
    Regression testing
    """

    @classmethod
    def setUpClass(cls):
        util.vprint('*** Starting %s' % cls.__name__)
        # XXX validate that target exists?
        cls.first_burst_values = [4096, 8192, 16384, 32768, 65536, 131972]
        cls.max_burst_values = [4096, 8192, 16384, 32768, 65536, 131072]
        cls.max_recv_values = [4096, 8192, 16384, 32768, 65536, 131072]

    def setUp(self):
        if Global.debug or Global.verbosity > 1:
            # this makes debug printing a little more clean
            print('', file=sys.stderr)
        res = util.run_cmd(['iscsiadm', '-m', 'node', '-T', Global.target, '-p', Global.ipnr, '--logout'], quiet_mode=True)
        if res not in [0, 21]:
            self.fail('logout failed')
        self.assertFalse(os.path.exists(Global.device), '%s: exists after logout!' % Global.device)

    def test_immediate_data(self):
        """
        Test No Immediate Data but Initial Request to Transmit
        """
        iscsi_data = IscsiData('No', 'Yes', 'None', 'None', 4096, 4096, 4096)
        iscsi_data.update_cfg(Global.target, Global.ipnr)
        res = util.run_cmd(['iscsiadm', '-m', 'node', '-T', Global.target, '-p', Global.ipnr, '--login'], quiet_mode=True)
        self.assertEqual(res, 0, 'cannot login to device')
        # wait a few seconds for the device to show up
        for i in range(10):
            if os.path.exists(Global.device):
                break
            os.sleep(1)
        self.assertTrue(os.path.exists(Global.device), '%s: does not exist after login' % Global.device)
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
        util.run_cmd(['iscsiadm', '-m', 'node', '-T', Global.target, '-p', Global.ipnr, '--logout'], quiet_mode=True)


if __name__ == '__main__':
    util.verify_needed_commands_exist(['parted', 'fio', 'mkfs', 'bonnie++', 'dd', 'iscsiadm'])
    # do our own hackery first, to get access to verbosity, debug, etc,
    # as well as add our own command-line options
    util.setup_testProgram_overrides()
    # now run the tests
    unittest.main()
