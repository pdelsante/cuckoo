# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import stat
import getpass
import logging
import subprocess

from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT, CUCKOO_ROOT
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Networking
from lib.cuckoo.common.utils import create_folder

log = logging.getLogger(__name__)

class Snort(Networking):
    """Snort Manager.

    This class handles the execution of the external snort instance.
    """

    def __init__(self):
        super(Snort, self).__init__()
        self.proc = None

    def start(self):
        """Start sniffing.
        @return: operation status.
        """
        if not self.options.snort:
            log.error("Please specify a path to snort, capture aborted")
            return False
        
        if not os.path.exists(self.options.snort):
            log.error("Snort does not exist at path \"%s\", snort capture "
                      "aborted" % self.options.snort)
            return False

        mode = os.stat(self.options.snort)[stat.ST_MODE]
        if mode and stat.S_ISUID != 2048:
            log.error("Snort is not accessible from this user, snort "
                      "capture aborted")
            return False

        if not self.machine:
            log.error("Please specify a virtual machine object to use, snort capture aborted")
            return False

        if not self.machine.interface:
            log.error("Network interface not defined, snort capture aborted")
            return False

        if not self.analysis_path:
            if self.task:
                self.analysis_path = os.path.join(CUCKOO_ROOT,
                                                  "storage",
                                                  "analyses",
                                                  str(self.task.id))
            else:
                log.error("You should specify the analysis path to save the log to, snort capture aborted")
                return False

        try:
            create_folder(self.analysis_path, "snort")
        except:
            log.error("Unable to create directory \"snort\" under \"%s\"", self.analysis_path)
            return False
        
        snort_capture_path = os.path.join(self.analysis_path, "snort")
        file_path = os.path.join(snort_capture_path, "snort.log")

        pargs = []
        if self.options.use_sudo:
            pargs.extend(["sudo"])
        
        pargs.extend([self.options.snort,
                      "-A", "fast",
                      "-i", self.machine.interface,
                      "-l", snort_capture_path,
                      "-N",
                      "-L", file_path,
                      ])
        
        if self.options.umask:
            pargs.extend(["-m", "%04d" %(self.options.umask)])
        
        if self.options.user:
            pargs.extend(["-u", self.options.user])
        
        # Only capture traffic from/to the current VM
        pargs.extend(["host", self.machine.ip])

        log.debug("Running snort with command: %s", " ".join(pargs))

        try:
            self.proc = subprocess.Popen(pargs,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        except (OSError, ValueError) as e:
            log.exception("Failed to start snort (interface=%s, "
                          "dump path=%s)" % (self.machine.interface, snort_capture_path))
            return False

        log.info("Started snort (interface=%s, dump path=%s)"
                 % (self.machine.interface, snort_capture_path))

        return True

    def stop(self):
        """Stop snort.
        @return: operation status.
        """
        if self.proc and not self.proc.poll():
            try:
                self.proc.terminate()
            except:
                try:
                    if not self.proc.poll():
                        log.debug("Killing snort")
                        self.proc.kill()
                except OSError as e:
                    # Avoid "trying to kill a died process" error.
                    log.debug("Error killing snort: %s. Continue" % e)
                    pass
                except Exception as e:
                    log.exception("Unable to stop the snort instance with pid %d"
                                  % self.proc.pid)
                    return False

        return True
