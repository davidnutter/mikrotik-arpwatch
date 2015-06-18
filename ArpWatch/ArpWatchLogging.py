# Copyright (C) 2014  Biomathematics and Statistics Scotland
#               
# Author: David Nutter (david.nutter@bioss.ac.uk)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#    Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
#    Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
#    Neither the name of Biomathematics and Statistics Scotland nor the
#    names of its contributors may be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import sys
import syslog

#Constants to set the default target
TARGET_CONSOLE=1
TARGET_SYSLOG=2

#Initialisation defaults. 
DEFAULT_LOG_LEVEL=syslog.LOG_NOTICE
LOG_FACILITY=syslog.LOG_USER

global_target=TARGET_CONSOLE
global_level=DEFAULT_LOG_LEVEL

#Symbol tables to convert numeric log levels into names. Only single
#levels supported.
SYMBOLIC_DISPATCH={
    "emergency": syslog.LOG_EMERG,
    "alert"    : syslog.LOG_ALERT,
    "critical" : syslog.LOG_CRIT,
    "error"    : syslog.LOG_ERR,
    "warning"  : syslog.LOG_WARNING,
    "notice"   : syslog.LOG_NOTICE,
    "info"     : syslog.LOG_INFO,
    "debug"    : syslog.LOG_DEBUG
    }

LEVEL_DISPATCH = dict((v,k) for k, v in SYMBOLIC_DISPATCH.iteritems())

SYMBOLIC_LEVEL_ORDER=['emergency', 'alert', 'critical', 'error', 'warning','notice', 'info', 'debug']

def init_logging(target=TARGET_CONSOLE,level=DEFAULT_LOG_LEVEL):
    global global_target
    global global_level

    if not type(level) is int:        
        raise RuntimeError("Unknown log level value %s" % level)
    
    global_target=target
    global_level=level
    
    if target==TARGET_CONSOLE:
        pass
    elif target==TARGET_SYSLOG:
        syslog.openlog("arpwatch",0,syslog.LOG_USER)
        syslog.setlogmask(syslog.LOG_UPTO(global_level))
    else:
        raise RuntimeError("Unknown target value")
                 
def log_message(priority,message):
    if global_target==TARGET_CONSOLE:
        sys.stderr.write(message.rstrip()+"\n")
    elif global_target==TARGET_SYSLOG:
        syslog.syslog(priority,message)

def symbolic_to_level(name):
    global SYMBOLIC_DISPATCH,DEFAULT_LOG_LEVEL
    
    if name is not None and SYMBOLIC_DISPATCH.has_key(name.lower()):
        return SYMBOLIC_DISPATCH[name.lower()]
    else:
        return DEFAULT_LOG_LEVEL

def level_to_symbolic(level):
    global LEVEL_DISPATCH,DEFAULT_LOG_LEVEL
    if level is not None and LEVEL_DISPATCH.has_key(int(level)):
        return LEVEL_DISPATCH[int(level)]
    else:
        return None

def is_symbolic_level(name):
    global SYMBOLIC_DISPATCH
    if name is not None:
        return SYMBOLIC_DISPATCH.has_key(name.lower())

    return False

def get_symbolic_levels():
    global SYMBOLIC_LEVEL_ORDER
    return SYMBOLIC_LEVEL_ORDER
