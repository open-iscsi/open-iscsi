"""
ISCSI classes and utilities
"""

from .util import *

class IscsiData:
    """
    Gather all the iscsi data in one place
    """
    imm_data_en = 'Yes'
    initial_r2t_en = 'No'
    hdrdgst_en = 'None,CRC32C'
    datdgst_en = 'None,CRC32C'
    first_burst = 256 * 1024
    max_burst = 16 * 1024 * 1024 - 1024
    max_recv_dlength = 128 * 1024
    max_r2t = 1
    # the target-name and IP:Port
    target = None
    ipnr = None

    def __init__(self,
            imm_data_en=imm_data_en,
            initial_r2t_en=initial_r2t_en,
            hdrdgst_en=hdrdgst_en,
            datdgst_en=datdgst_en,
            first_burst=first_burst,
            max_burst=max_burst,
            max_recv_dlength=max_recv_dlength,
            max_r2t=max_r2t):
        self.imm_data_en = imm_data_en
        self.initial_r2t_en = initial_r2t_en
        self.hdrdgst_en = hdrdgst_en
        self.datdgst_en = datdgst_en
        self.first_burst = first_burst
        self.max_burst = max_burst
        self.max_recv_dlength = max_recv_dlength
        self.max_r2t = max_r2t

    def update_cfg(self, target, ipnr):
        """
        Update the configuration -- we could do this by hacking on the
        appropriate DB file, but this is safer (and slower) by far
        """
        if Global.verbosity > 1:
            print('* ImmediateData = %s' % self.imm_data_en)
            print('* InitialR2T = %s' % self.initial_r2t_en)
            print('* HeaderDigest = %s' % self.hdrdgst_en)
            print('* DataDigest = %s' % self.datdgst_en)
            print('* FirstBurstLength = %d' % self.first_burst)
            print('* MaxBurstLength = %d' % self.max_burst)
            print('* MaxRecvDataSegmentLength = %d' % self.max_recv_dlength)
            print('* MaxOutstandingR2T = %d' % self.max_r2t)
        c = ['iscsiadm', '-m', 'node', '-T', target, '-p', ipnr, '-o', 'update']
        run_cmd(c + ['-n', 'node.session.iscsi.ImmediateData', '-v', self.imm_data_en])
        run_cmd(c + ['-n', 'node.session.iscsi.InitialR2T', '-v', self.initial_r2t_en])
        run_cmd(c + ['-n', 'node.conn[0].iscsi.HeaderDigest', '-v', self.hdrdgst_en])
        run_cmd(c + ['-n', 'node.conn[0].iscsi.DataDigest', '-v', self.datdgst_en])
        run_cmd(c + ['-n', 'node.session.iscsi.FirstBurstLength', '-v', str(self.first_burst)])
        run_cmd(c + ['-n', 'node.session.iscsi.MaxBurstLength', '-v', str(self.max_burst)])
        run_cmd(c + ['-n', 'node.conn[0].iscsi.MaxRecvDataSegmentLength', '-v', str(self.max_recv_dlength)])
        run_cmd(c + ['-n', 'node.session.iscsi.MaxOutstandingR2T', '-v', str(self.max_r2t)])
