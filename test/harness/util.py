"""
harness stuff (support) -- utility routines
"""

import os
import shutil
import sys
import unittest
import time
import tempfile
import re

from . import __version__ as lib_version

#
# globals
#
class Global:
    FSTYPE = os.getenv('FSTYPE', 'ext3')
    if os.getenv('MOUNTOPTIONS'):
        MOUNTOPTIONS = os.getenv('MOUNTOPTIONS').split(' ')
    else:
        MOUNTOPTIONS = []
    MOUNTOPTIONS += ['-t', FSTYPE]
    MKFSCMD = [os.getenv('MKFSCMD', 'mkfs.' + FSTYPE)]
    if os.getenv('MKFSOPTS'):
        MKFSCMD += os.getenv('MKFSOPTS').split(' ')
    BONNIEPARAMS = os.getenv('BONNIEPARAMS', '-r0 -n10:0:0 -s16 -uroot -f -q').split(' ')
    verbosity = 1
    debug = False
    # the target (e.g. "iqn.*")
    target = None
    # the IP and optional port (e.g. "linux-system", "192.168.10.1:3260")
    ipnr = None
    # the device that will be created when our target is connected
    device = None
    # the first and only partition on said device
    partition = None
    # optional override for fio disk testing block size(s)
    blocksize = None
    # subtests to run -- by default, all of them
    # XXX we should really look how many subtests there are, but there's
    # no good way to detect that.
    subtest_list = [i+1 for i in range(16)]
    # for timing
    timing = dict.fromkeys(['fio', 'sgdisk', 'dd', 'bonnie', 'mkfs', 'sleep'], 0.0)
    total_time = 0.0


def dprint(*args):
    """
    Print a debug message if in debug mode
    """
    if Global.debug:
        print('DEBUG: ', file=sys.stderr, end='')
        for arg in args:
            print(arg, file=sys.stderr, end='')
        print('', file=sys.stderr)

def vprint(*args):
    """
    Print a verbose message
    """
    if Global.verbosity > 1 and args:
        for arg in args:
            print(arg, end='')
        print('')

def run_cmd(cmd, output_save_file=None):
    """
    run specified command, waiting for and returning result
    """
    if Global.debug:
        cmd_str = ' '.join(cmd)
        if output_save_file:
            cmd_str += ' >& %s' % output_save_file
        dprint(cmd_str)
    pid = os.fork()
    if pid < 0:
        print("Error: cannot fork!", flie=sys.stderr)
        sys.exit(1)
    if pid == 0:
        # the child
        if output_save_file or not Global.debug:
            stdout_fileno = sys.stdout.fileno()
            stderr_fileno = sys.stderr.fileno()
            if output_save_file:
                new_stdout = os.open(output_save_file, os.O_WRONLY|os.O_CREAT|os.O_TRUNC,
                                     mode=0o664)
            else:
                new_stdout = os.open('/dev/null', os.O_WRONLY)
            os.dup2(new_stdout, stdout_fileno)
            os.dup2(new_stdout, stderr_fileno)
        os.execvp(cmd[0], cmd)
        # not reached
        sys.exit(1)

    # the parent
    wpid, wstat = os.waitpid(pid, 0)
    if wstat != 0:
        dprint("exit status: (%d) %d" % (wstat, os.WEXITSTATUS(wstat)))
    return os.WEXITSTATUS(wstat)

def new_initArgParsers(self):
    """
    Add  some options to the normal unittest main options
    """
    global old_initArgParsers

    old_initArgParsers(self)
    self._main_parser.add_argument('-d', '--debug', dest='debug',
            action='store_true',
            help='Enable developer debugging')
    self._main_parser.add_argument('-t', '--target', dest='target',
            action='store',
            help='Required: target name')
    self._main_parser.add_argument('-i', '--ipnr', dest='ipnr',
            action='store',
            help='Required: name-or-ip[:port]')
    self._main_parser.add_argument('-D', '--device', dest='device',
            action='store',
            help='Required: device')
    self._main_parser.add_argument('-B', '--blocksize', dest='blocksize',
            action='store',
            help='block size (defaults to an assortment of sizes)')
    self._main_parser.add_argument('-V', '--version', dest='version_request',
            action='store_true',
            help='Display Version info and exit')
    self._main_parser.add_argument('-l', '--list', dest='list_tests',
            action='store_true',
            help='List test cases and exit')
    self._main_parser.add_argument('-s', '--subtests', dest='subtest_list',
            action='store',
            help='Subtests to execute [default all, i.e. "1-16"]')

def print_suite(suite):
    """Print a list of tests from a test suite"""
    dprint("print_suite: entering for", suite)
    if hasattr(suite, '__iter__'):
        for x in suite:
            print_suite(x)
    else:
        print(suite)

def new_parseArgs(self, argv):
    """
    Gather globals from unittest main for local consumption -- this
    called to parse then validate the arguments, inside each TestCase
    instance.
    """
    global old_parseArgs, prog_name, parent_version, lib_version

    # actually parse the arguments
    old_parseArgs(self, argv)

    # now validate stuff
    if self.version_request:
        print('%s Version %s, harness version %s' % \
              (prog_name, parent_version, lib_version))
        sys.exit(0)
    Global.verbosity = self.verbosity
    Global.debug = self.debug
    if self.list_tests:
        print_suite(unittest.defaultTestLoader.discover('.'))
        sys.exit(0)
    for v in ['target', 'ipnr', 'device']:
        if getattr(self, v) is None:
            print('Error: "%s" required' % v.upper())
            sys.exit(1)
        setattr(Global, v, getattr(self, v))
    Global.blocksize = self.blocksize
    dprint("found: verbosity=%d, target=%s, ipnr=%s, device=%s, bs=%s" % \
            (Global.verbosity, Global.target, Global.ipnr, Global.device, Global.blocksize))
    # get partition from path
    device_dir = os.path.dirname(Global.device)
    if device_dir == '/dev':
        Global.partition = '%s1' % Global.device
    elif device_dir in ['/dev/disk/by-id', '/dev/disk/by-path']:
        Global.partition = '%s-part1' % Global.device
    else:
        print('Error: must start with "/dev" or "/dev/disk/by-{id,path}": %s' % \
                Global.device, file=sys.stderr)
        sys.exit(1)
    if self.subtest_list:
        if not user_spec_to_list(self.subtest_list):
            self._print_help()
            sys.exit(1)

def user_spec_to_list(user_spec):
    """
    We have 16 subtests. By default, we run them all, but if
    the user has specified a subset, like 'N' or 'N-M', then
    a list of the indicies they requested.

    XXX: expand to handle groups, e.g. 1,3-4,12 ???

    XXX: should we validate that the range will work, or just
    let an exception happen in that case?
    """
    pat_single = re.compile(r'(\d+)$')
    pat_range = re.compile(r'(\d+)-(\d+)$')
    found = False
    start_idx = None
    end_idx = None
    res = pat_range.match(user_spec)
    if res:
        # user wants just one subtest
        start_idx = int(res.group(1)) - 1
        end_idx = int(res.group(2))
        dprint("Found request for range: %d-%d" % (start_idx, end_idx))
        found = True
    else:
        res = pat_single.match(user_spec)
        if res:
            start_idx = int(res.group(1)) - 1
            end_idx = start_idx + 1
            dprint("Found request for single: %d-%d" % (start_idx, end_idx))
            found = True
    if not found:
        print('Error: subtest spec does not match N or N-M: %s' % user_spec)
    else:
        dprint("subtest_list before:", Global.subtest_list)
        Global.subtest_list = Global.subtest_list[start_idx:end_idx]
        dprint("subtest_list after:", Global.subtest_list)
    return found
    
def setup_testProgram_overrides(version_str, name):
    """
    Add in special handling for a couple of the methods in TestProgram (main)
    so that we can add parameters and detect some globals we care about
    """
    global old_parseArgs, old_initArgParsers, parent_version, prog_name

    old_initArgParsers = unittest.TestProgram._initArgParsers
    unittest.TestProgram._initArgParsers = new_initArgParsers
    old_parseArgs = unittest.TestProgram.parseArgs
    unittest.TestProgram.parseArgs = new_parseArgs
    parent_version = version_str
    prog_name = name

def verify_needed_commands_exist(cmd_list):
    """
    Verify that the commands in the supplied list are in our path
    """
    path_list = os.getenv('PATH').split(':')
    any_cmd_not_found = False
    for cmd in cmd_list:
        found = False
        for a_path in path_list:
            if os.path.exists('%s/%s' % (a_path, cmd)):
                found = True
                break
        if not found:
            print('Error: %s must be in your PATH' % cmd)
            any_cmd_not_found = True
    if any_cmd_not_found:
        sys.exit(1)


def run_fio():
    """
    Run the fio benchmark for various block sizes.
    
    Return zero for success.
    Return non-zero for failure and a failure reason.

    Uses Globals: partition, blocksize
    """
    if Global.blocksize is not None:
        dprint('Found a block size passed in: %s' % Global.blocksize)
        blocksizes = Global.blocksize.split(' ')
    else:
        dprint('NO Global block size pass in?')
        blocksizes = ['512', '1k', '2k', '4k', '8k',
                '16k', '32k', '75536', '128k', '1000000']
    # for each block size, do a read test, then a write test
    for bs in blocksizes:
        vprint('Running "fio" read/write/verify tests with 8/8/1 threads, bs=%s' % bs)
        # only support direct IO with aligned reads
        if bs.endswith('k'):
            direct=1
        else:
            direct=0
        ts = time.perf_counter()
        res = run_cmd(['fio', '--name=read-test', '--readwrite=randread',
            '--runtime=2s', '--numjobs=8', '--blocksize=%s' % bs, 
            '--offset=256k',
            '--direct=%d' % direct, '--filename=%s' % Global.partition])
        if res != 0:
            return (res, 'fio failed')
        res = run_cmd(['fio', '--name=write-test', '--readwrite=randwrite',
            '--runtime=2s', '--numjobs=8', '--blocksize=%s' % bs, 
            '--offset=256k',
            '--direct=%d' % direct, '--filename=%s' % Global.partition])
        if res != 0:
            return (res, 'fio failed')
        res = run_cmd(['fio', '--name=verify-test', '--readwrite=randwrite',
            '--runtime=2s', '--numjobs=1', '--blocksize=%s' % bs, 
            '--direct=%d' % direct, '--filename=%s' % Global.partition,
            '--offset=256k',
            '--verify=md5', '--verify_state_save=0'])
        if res != 0:
            return (res, 'fio failed')
        te = time.perf_counter()
        Global.timing['fio'] += te - ts
    return (0, 'Success')

def wait_for_path(path, present=True, amt=10):
    """Wait until a path exists or is gone"""
    dprint("Looking for path=%s, present=%s" % (path, present))
    for i in range(amt):
        sleep_some(1)
        if os.path.exists(path) == present:
            dprint("We are Happy :) present=%s, cnt=%d" % (present, i))
            return True
    dprint("We are not happy :( present=%s actual=%s after %d seconds" % \
           (present, os.path.exists(path), amt))
    return False

def wipe_disc():
    """
    Wipe the label and partition table from the disc drive -- the sleep-s
    are needed to give the async OS and udev a chance to notice the partition
    table has been erased
    """
    # zero out the label and parition table
    vprint('Running "sgdisk" and "dd" to wipe disc label, partitions, and filesystem')
    sleep_some(1)
    ts = time.perf_counter()
    res = run_cmd(['sgdisk', '--clear', Global.device])
    te = time.perf_counter()
    Global.timing['sgdisk'] += te -ts
    if res != 0:
        if res == 4:
            dprint("Oh oh -- 'clear' failed! trying one more time ...")
        ts = time.perf_counter()
        res = run_cmd(['sgdisk', '--clear', Global.device])
        te = time.perf_counter()
        if res != 0:
            return (res, '%s: could not zero out label after two tries: %d' % \
                    (Global.device, res))
        Global.timing['sgdisk'] += te - ts
    ts = time.perf_counter()
    res = run_cmd(['dd', 'if=/dev/zero', 'of=%s' % Global.device, 'bs=256k', 'count=20', 'oflag=direct'])
    te = time.perf_counter()
    if res != 0:
        return (res, '%s: could not zero out filesystem: %d' % (Global.device, res))
    Global.timing['dd'] += te - ts
    return (0, 'Success')
    
def run_parted():
    """
    Run the parted program to ensure there is one partition,
    and that it covers the whole disk

    Return zero for success and the device pathname.
    Return non-zero for failure and a failure reason.

    Uses Globals: device, partition
    """
    (res, reason) = wipe_disc()
    if res != 0:
        return (res, reason)
    # ensure our partition file is not there, to be safe
    if not wait_for_path(Global.partition, present=False, amt=30):
        return (1, '%s: Partition already exists?' % Global.partition)
    # make a label, then a partition table with one partition
    vprint('Running "parted" to create a label and partition table')
    res = run_cmd(['parted', Global.device, 'mklabel', 'gpt'])
    if res != 0:
        return (res, '%s: Could not create a GPT label' % Global.device)
    res = run_cmd(['parted', '-a', 'none', Global.device, 'mkpart', 'primary', '0', '100%'])
    if res != 0:
        return (res, '%s: Could not create a primary partition' % Global.device)
    # wait for the partition to show up
    if not wait_for_path(Global.partition):
        return (1, '%s: Partition never showed up?' % Global.partition)
    # success
    return (0, 'Success')

def run_mkfs():
    vprint('Running "mkfs" to to create filesystem')
    ts = time.perf_counter()
    res = run_cmd(Global.MKFSCMD + [ Global.partition ] )
    te = time.perf_counter()
    if res != 0:
        return (res, '%s: mkfs failed (%d)' % (Global.partition, res))
    Global.timing['mkfs'] += te - ts
    return (0, 'Success')

def run_bonnie():
    # make a temp dir and mount the device there
    with tempfile.TemporaryDirectory() as tmp_dir:
        vprint('Running "mount" to mount the filesystem')
        res = run_cmd(['mount'] + Global.MOUNTOPTIONS + [Global.partition, tmp_dir])
        if res != 0:
            return (res, '%s: mount failed (%d)' % (Global.partition, res))
        # run bonnie++ on the new directory
        vprint('Running "bonnie++" on the filesystem')
        ts = time.perf_counter()
        res = run_cmd(['bonnie++'] + Global.BONNIEPARAMS + ['-d', tmp_dir])
        te = time.perf_counter()
        if res != 0:
            return (res, '%s: umount failed (%d)' % (tmp_dir, res))
        Global.timing['bonnie'] += te - ts
        # unmount the device and remove the temp dir
        vprint('Running "umount" to unmount the filesystem')
        res = run_cmd(['umount', tmp_dir])
        if res != 0:
            return (res, '%s: umount failed (%d)' % (tmp_dir, res))
    return (0, 'Success')

def sleep_some(s):
    # sleep s seconds
    ts = time.perf_counter()
    time.sleep(s)
    te = time.perf_counter()
    Global.timing['sleep'] += te - ts
