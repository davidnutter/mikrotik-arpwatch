#!/usr/bin/python

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

from optparse import OptionParser

from ArpWatch import *
import ConfigParser
import errno
import grp
import os
import pwd
import re
import resource
import select
import signal
import socket
import sys
import syslog
import time
import traceback

#GLOBAL CONFIG OPTIONS

#Default API port on Routerboards. Can be specified in --host argument if change is needed
DEFAULT_PORT=8728

#Hardcode our config file path 
CONFIG_FILE=["/etc/mikrotik-arpwatch.cfg", "mikrotik-arpwatch.cfg"]

# File mode creation mask of the daemon.
UMASK = 0

# Default working directory for the daemon.
WORKDIR = "/"

# Default maximum for the number of available file descriptors.
MAXFD = 1024

# The standard I/O file descriptors are redirected to /dev/null by default.
if (hasattr(os, "devnull")):
   REDIRECT_TO = os.devnull
else:
   REDIRECT_TO = "/dev/null"

#GLOBAL VARIABLES (WRITABLE)
#---------------------------

#Allow access to the options set from config file/commandline
global_options=None

#Arp data object, accessible globally for convenience
global_arp_data=None


def set_default(section,element,cfg_parser,option_parser):
   if cfg_parser.has_option(section,element):
      option_parser.set_default( "%s_%s" % (section,element),cfg_parser.get(section,element))

def set_default_list(section,element,cfg_parser,option_parser):
   if cfg_parser.has_option(section,element):
      optionlist=cfg_parser.get(section,element).split("\n")
      option_parser.set_default( "%s_%s" % (section,element),optionlist)
   
def process_args(): 
    config = ConfigParser.SafeConfigParser()

    file_read_success=False
    
    for cfg_file in CONFIG_FILE:
       if not os.path.isfile(cfg_file):
          continue 
       
       try:       
          config.readfp(open(cfg_file))
          file_read_success=True
       except IOError,err:
          sys.stderr.write("Unable to read default config file %s.\nReason: %s\n" %(cfg_file,err))

    if not file_read_success:
       sys.stderr.write("No config files from the list %s could be read. Quitting\n" % ",".join(CONFIG_FILE))

    parser = OptionParser(usage="%prog [options]",version="%prog 0.1")

    #Config file options
    parser.add_option("","--datafile",type="string",dest="arpwatch_datafile",
                      help="Name of the datafile to save IP:MAC pairings")
    parser.add_option("","--keepdays",type="int",dest="arpwatch_keepdays",
                      help="Number of days to save IP:MAC pairings")

   
    parser.add_option("","--log-level",type="string",dest="daemon_log_level",
                      help="Log level to log upto. One of 'emergency', 'alert', 'critical', 'error', 'warning','notice', 'info', 'debug'") 
    parser.add_option("","--run-user",type="string",dest="daemon_user",
                      help="Username to run under when privileges are dropped")
    parser.add_option("","--run-group",type="string",dest="daemon_group",
                      help="Group to run under when privileges are dropped")
    parser.add_option("","--pid-file",type="string",dest="daemon_pid_file",
                      help="PID file to use (only relevant in Daemon mode)")
    
    parser.add_option("","--write-delay",type="int",dest="schedule_writedelay",
                      help="The minimum delay (in seconds) that will elapse between writes of the arp.dat file in normal usage")
    parser.add_option("","--cleanup-delay",type="int",dest="schedule_cleanupdelay",
                      help="The minimum delay (in seconds) that will elapse between cleanup of the arp data in normal usage")
    parser.add_option("","--select-timout",type="int",dest="schedule_select_timeout",
                      help="The maximum time to wait for messages from the routerboard before going and doing something else")

    parser.add_option("-u","--username",type="string",dest="api_user",
                      help="Username to connect to the routerboard with")
    parser.add_option("-p","--password",type="string",dest="api_password",
                      help="Password to connect to the routerboard with")
    parser.add_option("","--host",type="string",dest="api_host",                     
                      help="Hostname:port combo specifying the routerboard to connect to")

    parser.add_option("","--include-mac",action="append",dest="patterns_include_mac",
                      help="Supply a regex which matches MAC addresses to be explicitly included in the ARP data")
    parser.add_option("","--exclude-mac",action="append",dest="patterns_exclude_mac",
                      help="Supply a regex which matches MAC addresses to be explicitly excluded in the ARP data")
    parser.add_option("","--include-ip",action="append",dest="patterns_include_ip",
                      help="Supply a regex which matches IP addresses to be explicitly included in the ARP data")
    parser.add_option("","--exclude-ip",action="append",dest="patterns_exclude_ip",
                      help="Supply a regex which matches IP addresses to be explicitly excluded in the ARP data")
    
    #Set defaults from config file
    set_default("arpwatch","datafile",config,parser)
    set_default("arpwatch","keepdays",config,parser)

    set_default("daemon","log_level",config,parser)
    set_default("daemon","user",config,parser)
    set_default("daemon","group",config,parser)
    set_default("daemon","pid_file",config,parser)
    
    set_default("schedule","writedelay",config,parser)
    set_default("schedule","cleanupdelay",config,parser)
    set_default("schedule","select_timeout",config,parser)

    set_default("api","user",config,parser)
    set_default("api","password",config,parser)
    set_default("api","host",config,parser)

    set_default_list("patterns","include_mac",config,parser)
    set_default_list("patterns","exclude_mac",config,parser)
    set_default_list("patterns","include_ip",config,parser)
    set_default_list("patterns","exclude_ip",config,parser)

    #Regular command line options
    parser.add_option("-t","--test",type="string",dest="test_data",
                      help="Do not connect to the routerboard. Instead process the input file and act accordingly. Will also print configuration information")

    parser.add_option("","--show-config",action="store_true",dest="print_config", default=False,
                      help="Do not connect to the the routerboard, just print configuration information")
    parser.add_option("-D","--no-detach",action="store_true",dest="nodetach", default=False,
                      help="Do not detach from console (daemonise). Instead, remain attached and print actions as they occur")

    
    (options,args) = parser.parse_args()
        
    return (options,args)
        
def establish_session():
    "Create a session with the routerboard API. Failures are logged. Socket (or None in the case of failure) is returned"
    hostbits = global_options.api_host.split(":")
    if len(hostbits) == 1:
        host = hostbits[0]
        port = int(DEFAULT_PORT)
    elif len(hostbits) ==2:
        host = hostbits[0]
        port = int(hostbits[1])
    else:
        ArpWatchLogging.log_message(syslog.LOG_ERR,"Host spec %s does not appear to be in host.name:port format. Aborting" % global_options.host)
        sys.exit(1)
    
    try:
        addr=socket.gethostbyname(host)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((addr, port))  

        apiros = RosAPI.ApiRos(s)
        (login_ok,message)=apiros.login(global_options.api_user,global_options.api_password)

        if not login_ok:
            ArpWatchLogging.log_message(syslog.LOG_ERR,"Login to routerboard failed. Potential Username/password issue.\nRouterboard responded: '%s' " % message)
            return None

        return apiros
    except Exception,err:
        ArpWatchLogging.log_message(syslog.LOG_ERR,"Error creating session to %s@%s:%s.\nReason: '%s'" % (global_options.api_user,host,port,err))

    return None    

def process_arp(response):

    if response is None:
        return

    ArpWatchLogging.log_message(syslog.LOG_DEBUG,"Processing API response\n"+'\n'.join(response))
    
    #We're only interested in actual ARP responses, not other things the API can send us.
    arp_response=dict()
    
    for resp_line in response:
        resp_line=resp_line.rstrip()

        match=re.match("=([^=]+)=(.*)$",resp_line)
        if match is not None:
            arp_response[match.group(1)]=match.group(2)

    if arp_response.has_key("address") and arp_response.has_key("mac-address"):
        global_arp_data.update_arp_entry(arp_response["address"],arp_response["mac-address"])                                

def test_mode():
    if not os.path.isfile(global_options.test_data):
        ArpWatchLogging.log_message(syslog.LOG_ERR,"Test data file '%s' is missing" % global_options.test_data)
        sys.exit(1)
        
    ArpWatchLogging.log_message(syslog.LOG_INFO,"Starting test mode using file '%s'" % global_options.test_data)
    
    try:
        input_data = open(global_options.test_data)
        
        rb_sentence=""
        
        for line in input_data:
            line=re.sub('\s*#.*$','',line)
            if len(line.rstrip())==0:
                if len(rb_sentence.rstrip()) > 0:
                    process_arp(rb_sentence.split("\n"))
                    rb_sentence=""
                    continue
                
            if len(line) > 0:
                rb_sentence=rb_sentence+line                    
                    
        input_data.close()

    except IOError,err:
        ArpWatchLogging.log_message(syslog.LOG_ERR,
                                    "Error reading testdata file '%s'\nReason: '%s'" %
                                    (global_options.test_data,err))
        sys.exit(1)
        
    for (key,arp_entry) in global_arp_data.arp_table.items():
        ArpWatchLogging.log_message(syslog.LOG_DEBUG,
                                    "Arp entry: %-20s %-20s %-20s %s"
                                    %(arp_entry.mac,arp_entry.ip,arp_entry.epoch,arp_entry.host))
                                        
    global_arp_data.write_file()

def data_mode():
   signal.signal(signal.SIGTERM,sigterm_handler)
   signal.signal(signal.SIGHUP,sighup_handler)
   signal.signal(signal.SIGUSR1,sigusr1_handler)
           
   ArpWatchState.next_write=global_arp_data.last_written+global_options.schedule_writedelay
   ArpWatchState.next_cleanup=global_arp_data.last_written+global_options.schedule_cleanupdelay
   
   ArpWatchLogging.log_message(syslog.LOG_NOTICE,"Starting Mikrotik Arpwatch. PID %d" % os.getpid())
   ArpWatchLogging.log_message(syslog.LOG_INFO,"Next data file write: %s" %
                               time.strftime("%F %X %Z",time.gmtime(ArpWatchState.next_write)))
   ArpWatchLogging.log_message(syslog.LOG_INFO,"Next data cleanup write: %s" %
                               time.strftime("%F %X %Z",time.gmtime(ArpWatchState.next_cleanup)))
        
   while ArpWatchState.keep_running:
      try:

         #TODO: allow multiple routerboard sessions to be established
         #here; select will pick up the results

         rb_api=establish_session()
         
         if rb_api is None:
            #TODO: may be useful to distinguish between login failures
            #(abort immediately) or timeouts, in which case retrying
            #is useful            
            break
                 
         rb_api.writeSentence(["/ip/arp/listen"])

         while ArpWatchState.keep_running:
            r = select.select([rb_api.sk], [], [], global_options.schedule_select_timeout )
            if rb_api.sk in r[0]: 
               x = rb_api.readSentence()
               process_arp(x)

            current_time=int(time.time())

            if current_time > ArpWatchState.next_cleanup:
               global_arp_data.clean_stale_arp(global_options.arpwatch_keepdays)
               ArpWatchState.next_cleanup=current_time+global_options.schedule_cleanupdelay
                        
            if current_time > ArpWatchState.next_write:
               global_arp_data.write_file()
               ArpWatchState.next_write=current_time+global_options.schedule_writedelay
               
      except select.error,select_err:
         (errnum,message)=select_err
         
         #Ignore EINTR so signal handlers can do their thing
         if errnum!=errno.EINTR:
            ArpWatchLogging.log_message(syslog.LOG_ERR,"select call aborted. Reason '%s'\n" % message)                    
      except RosAPI.ConnectionError,conn_err: 
         ArpWatchLogging.log_message(syslog.LOG_INFO,"Lost connection to routerboard. Will attempt reconnection.")
      except KeyboardInterrupt,int_err: 
         ArpWatchLogging.log_message(syslog.LOG_NOTICE,"Interrupt received, shutting down cleanly")                
         break


   global_arp_data.write_file()
             
#SIGHUP in daemon mode will force data file write and cleanup to take place.
#In terminal mode, shutdown will occur
#
#TODO: could consider rereading the config file in daemon mode but a
#straight restart might be easier due to dropping privileges
def sighup_handler(signum,frame):
    if global_options.nodetach:
        ArpWatchLogging.log_message(syslog.LOG_NOTICE,"SIGHUP recieved, shutting down")
        ArpWatchState.keep_running=False
    else:
        ArpWatchLogging.log_message(syslog.LOG_NOTICE,"SIGHUP recieved, forcing cleanup and datafile write")
        current_time=int(time.time())
        ArpWatchState.next_write=current_time-5
        ArpWatchState.next_cleanup=current_time-5
     

#Shutdown process cleanly
def sigterm_handler(signum,frame):
    ArpWatchLogging.log_message(syslog.LOG_NOTICE,"SIGTERM recieved, shutting down")
    ArpWatchState.keep_running=False

#Force cleanup and datafile write
def sigusr1_handler(signum,frame):
    ArpWatchLogging.log_message(syslog.LOG_NOTICE,"SIGUSR1 recieved, forcing cleanup and datafile write")
    current_time=int(time.time())
    ArpWatchState.next_write=current_time-5
    ArpWatchState.next_cleanup=current_time-5

def create_daemon():
    #See here for inspiration: http://code.activestate.com/recipes/278731/
    try:
        pid = os.fork() #Fork a child
    except OSError, e:
        raise Exception, "%s [%d]" % (e.strerror, e.errno)

    if (pid == 0):	
        os.setsid()
      
        try:
            pid = os.fork()	# Fork a second child.
        except OSError, e:
            raise Exception, "%s [%d]" % (e.strerror, e.errno)

        if (pid == 0):	
            os.chdir(WORKDIR)

            os.umask(UMASK)
        else:
            os._exit(0)	# Exit parent (the first child) of the second child.
    else:
        os._exit(0)	# Exit parent of the first child.

    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    
    if (maxfd == resource.RLIM_INFINITY):
        maxfd = MAXFD
  
    # Iterate through and close all file descriptors.
    for fd in range(0, maxfd):
        try:
            os.close(fd)
        except OSError:	# ERROR, fd wasn't open to begin with (ignored)
            pass

    # Redirect standard file descriptors
    os.open(REDIRECT_TO, os.O_RDWR)	# standard input (0)
   
    # Duplicate standard input to standard output and standard error.
    os.dup2(0, 1)			# standard output (1)
    os.dup2(0, 2)			# standard error (2)

    # Create PID file before privilege drop
    try:
        pid_file=open(global_options.daemon_pid_file,'w')
        pid_file.write("%d\n" % os.getpid())
        pid_file.flush() 
        pid_file.close()
    except Exception,err:
        ArpWatchLogging.log_message(syslog.LOG_ERR,
                                    "Error creating PID file %s for daemon process. Aborting. Error was '%s'" %
                                    (global_options.daemon_pid_file,err))
        os._exit(1)
   
    return(0) 

def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    if os.getuid() != 0:
        return

    die_horribly=False
    new_uid=None
    new_gid=None
    
    try:
        new_uid = pwd.getpwnam(uid_name).pw_uid
    except KeyError,err:
        ArpWatchLogging.log_err(syslog.LOG_ERR,"Drop privileges failed: User name '%s' does not exist" % uid_name)
        die_horribly=True
        
    try:
        new_gid = grp.getgrnam(gid_name).gr_gid
    except KeyError,err:
        ArpWatchLogging.log_err(syslog.LOG_ERR,"Drop privileges failed: Group name '%s' does not exist" % uid_name)
        die_horribly=True
        
    if die_horribly:
        sys.exit(1)
        
    ArpWatchLogging.log_message(syslog.LOG_INFO,"Dropping privileges to %s:%s" % (uid_name, gid_name))
    
    os.setgroups([])
    os.setgid(new_gid)
    os.setuid(new_uid)

    old_umask = os.umask(077)
    
def main():

    global global_arp_data,global_options
    
    (options,args) = process_args()

    global_options=options    

    if global_options.print_config or global_options.test_data:
       print "Current configuration:"
       for option,value in options.__dict__.items():
          print "%-20s = %s" % (option,value)
          
       if global_options.print_config:
          sys.exit(0)                  

    global_arp_data=ArpData.ArpData(global_options.arpwatch_datafile)

    #Validate options TODO: more to be done here...
    option_error=False
    if not ArpWatchLogging.is_symbolic_level(global_options.daemon_log_level):
       ArpWatchLogging.log_message(syslog.LOG_ERR,"Option daemon_log_level must have a value from the range %s " % ",".join(ArpWatchLogging.get_symbolic_levels()) )
       option_error=True

    #Get logging going ASAP
    if not (options.nodetach or options.test_data):
       numeric_log_level=ArpWatchLogging.symbolic_to_level(global_options.daemon_log_level)
       ArpWatchLogging.init_logging(target=ArpWatchLogging.TARGET_SYSLOG,level=numeric_log_level)

    if global_options.schedule_writedelay < 1:
       ArpWatchLogging.log_message(syslog.LOG_ERR,"Option schedule_writedelay must have positive integer value")
       option_error=True
       
    if global_options.patterns_include_mac is not None:
       for pattern in global_options.patterns_include_mac:
          global_arp_data.include_mac_address(pattern)

    if global_options.patterns_exclude_mac is not None:
       for pattern in global_options.patterns_exclude_mac:
          global_arp_data.exclude_mac_address(pattern)

    if global_options.patterns_include_ip is not None:
       for pattern in global_options.patterns_include_ip:
          global_arp_data.include_ip_address(pattern)

    if global_options.patterns_exclude_ip is not None:
       for pattern in global_options.patterns_exclude_ip:
          global_arp_data.exclude_ip_address(pattern)
          
    if option_error:
       sys.exit(1)

    try:
       #Options OK so daemonise unless we're in test mode or forced to foreground 
       if not (options.nodetach or options.test_data):
          create_daemon()
          drop_privileges(global_options.daemon_user,global_options.daemon_group)

       global_arp_data.read_file()
       global_arp_data.clean_stale_arp(global_options.arpwatch_keepdays)   

       if global_options.test_data:
          test_mode()
       else:       
          data_mode()
    except Exception,err:
       ArpWatchLogging.log_message(syslog.LOG_ERR,"Global exception handler triggered. Trace:\n%s" % traceback.format_exc())
       if global_options.nodetach or global_options.test_data:
          sys.exit(1) #Exit with cleanup in non-daemon mode
       else:
          os._exit(1) #Exit without cleanup in daemon mode
                
class ArpWatchState:
    keep_running=True
    next_cleanup=0
    next_write=0    
    

    
if __name__ == '__main__':
    main()
