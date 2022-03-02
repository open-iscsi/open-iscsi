"""
tests -- the actual TestCase (just one)
"""

import sys
import os
import unittest
import time

from . import util
from .util import Global
from .iscsi import IscsiData


def s2dt(s):
    # seconds to "HH:MM:SS.sss"
    s_orig = s
    hrs = s / 3600
    s -= (int(hrs) * 3600)
    mins = s / 60
    s -= (int(mins) * 60)
    a_str="%02d:%02d:%06.3f" % (hrs, mins, s)
    dprint("s2dt: %f -> %s" % (s_orig, a_str))
    return a_str


def print_time_values():
    # print out global exec time values
    util.vprint('')
    util.vprint('Times spent running sub-programs:')
    ttl_time = 0.0
    for s in Global.timing.keys():
        v = Global.timing[s]
        r = s2dt(v)
        ttl_time += v
        util.vprint('  %10s = %s' % (s, r))
    util.vprint('    =======================')
    util.vprint('  %10s = %s' % ('Total', s2dt(ttl_time)))
    util.vprint('')
    util.vprint('Total test-run time: %s' % (s2dt(Global.total_time)))


class TestRegression(unittest.TestCase):
    """
    Regression testing
    """

    @classmethod
    def setUpClass(cls):
        util.verify_needed_commands_exist(['parted', 'fio', Global.MKFSCMD[0], 'bonnie++', 'sgdisk', 'iscsiadm'])
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
        cls.time_start = time.perf_counter()

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

    def test_InitialR2T_on_ImmediateData_off(self):
        """Test Initial Request to Transmit on, but Immediate Data off"""
        i = 1
        for v in self.param_values:
            with self.subTest('Testing FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v), i=i):
                if i not in Global.subtest_list:
                    util.vprint('Skipping subtest %d: FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v) % i)
                else:
                    util.vprint('Running subtest %d: FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v) % i)
                    self.iscsi_logout()
                    iscsi_data = IscsiData('No', 'Yes', 'None', 'None', v[0], v[1], v[2])
                    iscsi_data.update_cfg(Global.target, Global.ipnr)
                    self.run_the_rest()
            i += 1

    def test_InitialR2T_off_ImmediateData_on(self):
        """Test Initial Request to Transmit off, Immediate Data on"""
        i = 1
        for v in self.param_values:
            with self.subTest('Testing FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v), i=i):
                if i not in Global.subtest_list:
                    util.vprint('Skipping subtest %d: FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v) % i)
                else:
                    util.vprint('Running subtest %d: FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v) % i)
                    self.iscsi_logout()
                    iscsi_data = IscsiData('Yes', 'No', 'None', 'None', v[0], v[1], v[2])
                    iscsi_data.update_cfg(Global.target, Global.ipnr)
                    self.run_the_rest()
            i += 1

    def test_InitialR2T_on_ImmediateData_on(self):
        """Test Initial Request to Transmit and Immediate Data on"""
        i = 1
        for v in self.param_values:
            with self.subTest('Testing FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v), i=i):
                if i not in Global.subtest_list:
                    util.vprint('Skipping subtest %d: FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v) % i)
                else:
                    util.vprint('Running subtest %d: FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v) % i)
                    self.iscsi_logout()
                    iscsi_data = IscsiData('Yes', 'Yes', 'None', 'None', v[0], v[1], v[2])
                    iscsi_data.update_cfg(Global.target, Global.ipnr)
                    self.run_the_rest()
            i += 1

    def test_InitialR2T_off_ImmediateData_off(self):
        """Test Initial Request to Transmit and Immediate Data off"""
        i = 1
        for v in self.param_values:
            with self.subTest('Testing FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v), i=i):
                if i not in Global.subtest_list:
                    util.vprint('Skipping subtest %d: FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v) % i)
                else:
                    util.vprint('Running subtest %d: FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v) % i)
                    self.iscsi_logout()
                    iscsi_data = IscsiData('No', 'No', 'None', 'None', v[0], v[1], v[2])
                    iscsi_data.update_cfg(Global.target, Global.ipnr)
                    self.run_the_rest()
            i += 1

    def test_HdrDigest_on_DataDigest_off(self):
        """Test With Header Digest"""
        i = 1
        for v in self.param_values:
            with self.subTest('Testing FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v), i=i):
                if i not in Global.subtest_list:
                    util.vprint('Skipping subtest %d: FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v) % i)
                else:
                    util.vprint('Running subtest %d: FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v) % i)
                    self.iscsi_logout()
                    iscsi_data = IscsiData('No', 'Yes', 'CRC32C', 'None', v[0], v[1], v[2])
                    iscsi_data.update_cfg(Global.target, Global.ipnr)
                    self.run_the_rest()
            i += 1

    def test_HdrDigest_on_DataDigest_on(self):
        """Test With Header Digest"""
        i = 1
        for v in self.param_values:
            with self.subTest('Testing FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v), i=i):
                if i not in Global.subtest_list:
                    util.vprint('Skipping subtest %d: FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v) % i)
                else:
                    util.vprint('Running subtest %d: FirstBurst={} MaxBurst={} MaxRecv={}'.format(*v) % i)
                    self.iscsi_logout()
                    iscsi_data = IscsiData('No', 'Yes', 'CRC32C', 'CRC32C', v[0], v[1], v[2])
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
        # run parted to partition the disc with one whole disk partition
        (res, reason) = util.run_parted()
        self.assertEqual(res, 0, reason)
        # run fio to test file IO
        (res, reason) = util.run_fio()
        self.assertEqual(res, 0, reason)
        # wait a bit for cache to flush
        util.sleep_some(1)
        # make a filesystem
        (res, reason) = util.run_mkfs()
        self.assertEqual(res, 0, reason)
        # run bonnie++ to test the filesystem IO
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
        Global.total_time = time.perf_counter() - cls.time_start
        print_time_values()
