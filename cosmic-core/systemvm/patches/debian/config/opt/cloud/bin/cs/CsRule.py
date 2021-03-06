# -- coding: utf-8 --

import logging

import CsHelper


class CsRule:
    """ Manage iprules
    Supported Types:
    fwmark
    """

    def __init__(self, dev):
        self.dev = dev
        self.tableNo = int(dev[3:])
        self.table = "Table_%s" % (dev)

    def addMark(self):
        if not self.findMark():
            cmd = "ip rule add fwmark %s table %s" % (self.tableNo, self.table)
            CsHelper.execute(cmd)
            logging.info("Added fwmark rule for %s" % (self.table))

    def findMark(self):
        srch = "from all fwmark %s lookup %s" % (hex(self.tableNo), self.table)
        for i in CsHelper.execute("ip rule show"):
            if srch in i.strip():
                return True
        return False
