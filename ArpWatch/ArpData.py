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

import ArpWatchLogging
import math,os,re,shutil,socket,syslog,tempfile,time
        
class ArpEntry:
    "Represent ARP table entry"
    def __init__(self,ip,mac,epoch=int(time.time()),host=None):
        self.ip=ip
        self.mac=mac
        self.epoch=epoch
        
        if host is not None:
            self.host=host
        else:
            try:
                hostbits=socket.gethostbyaddr(ip) #TODO: this might be slow due to timeout issues; look at pydns if required
                self.host=hostbits[0].split(".")[0]
            except Exception,err:
                self.host=ip
                

    def equals(self,other_entry):
        "Return true if this entry is identical in all ways to the other entry"
        if isinstance(other_entry,ArpEntry):
            return (self.ip==other_entry.ip and
                    self.mac==other_entry.mac and
                    self.epoch==other_entry.epoch and
                    self.host==other_entry.host)
        return False

    def equivalent(self,other_entry):
        "Return true if IP/MAC pairing is the same as in other_entry"
        if isinstance(other_entry,ArpEntry):
            return (self.ip==other_entry.ip and
                    self.mac==other_entry.mac)
        return False

    def refresh(self):
        "Refresh the epoch time associated with this IP/MAC pairing to the current local time"
        self.epoch=int(time.time())

    def hash_key(self):
        return self.ip+"_"+self.mac
        

    #TODO: CIDR would be a better way than regex of doing ip include/exclude. 
class ArpData:
    
    def __init__(self,file_name):
        self.file_last_written=0
        self.file_name=file_name
        self.include_macaddr=None
        self.exclude_macaddr=None
        self.include_ipaddr=None
        self.exclude_ipaddr=None
        self.arp_table=dict()
        
    def read_file(self,clear_table=True):

        if clear_table:
            self.clear_table()

        ArpWatchLogging.log_message(syslog.LOG_INFO,"Reading ARP data file '%s'" % self.file_name)
        
        if not os.path.isfile(self.file_name):
            ArpWatchLogging.log_message(syslog.LOG_INFO,"ARP data file %s does not exist. It will be created when next written" % self.file_name)
            return True
        
        try:
            self.last_written=os.stat(self.file_name).st_mtime
            
            f = open(self.file_name)

            for line in f:
                try:
                    (mac,ip,epoch,host)=line.split("\t")
                    
                    entry=ArpEntry(ip,mac,int(epoch),host.rstrip())
                    self.arp_table[entry.hash_key()]=entry
                except Exception,err:
                    ArpWatchLogging.log_message(syslog.LOG_WARN,"Ignoring invalid ARP data line '%s'" % line)
                    continue
            f.close()
            return True
        
        except IOError,err:
            ArpWatchLogging.log_message(syslog.LOG_ERR,"Unable to read ARP data file '%s'.\nReason: '%s'" %(self.file_name,err))
            if clear_table:
                self.clear_table()
            return False

    def clear_table(self):
        "clear the arp table of data"

        ArpWatchLogging.log_message(syslog.LOG_INFO,"Clearing ARP data table")
        self.arp_table=dict()
        self.last_written=0
        
    def write_file(self):
        "write out the arp data in the arpwatch format"
        try:
            ArpWatchLogging.log_message(syslog.LOG_INFO,"Writing ARP data file '%s'" %(self.file_name))
            temp = tempfile.NamedTemporaryFile()
            for entry in self.arp_table.values():
                temp.write("%s\t%s\t%d\t%s\n" % ( entry.mac,entry.ip,entry.epoch,entry.host ))            
            temp.flush()
            shutil.copy(temp.name,self.file_name)
            temp.close()
            self.last_written=int(time.time())
        except IOError,err:
            ArpWatchLogging.log_message(syslog.LOG_ERR,"Unable to write to %s\n. Reason '%s'" % (self.file_name,err))

    def update_arp_entry(self,ip,mac):
        "update/create an entry for the specified ip/mac pair"

        if ip is None or mac is None:
            ArpWatchLogging.log_message(syslog.LOG_DEBUG,"Missing IP/Mac address when updating arp entries. Ignoring. ")
            return

        if not self.ip_address_included(ip):
            ArpWatchLogging.log_message(syslog.LOG_DEBUG,"IP address %s excluded by pattern rule. Ignoring. " % ip )
            return
        
        if not self.mac_address_included(mac):
            ArpWatchLogging.log_message(syslog.LOG_DEBUG,"MAC address %s excluded by pattern rule. Ignoring. " % mac )
            return
        
        ArpWatchLogging.log_message(syslog.LOG_INFO,"Updating ARP entry for %s %s" % (ip,mac))
        
        #TODO: better input validation
        key=ip+"_"+mac

        if self.arp_table.has_key(key):    
            entry = self.arp_table[ key ]
            entry.epoch=int(time.time())
        else:
            entry=ArpEntry(ip,mac)
            self.arp_table[ entry.hash_key() ]=entry;

    def entry(self,ip,mac):
        "Retrieve an entry, or None if entry does not exist"
        if ip is None or mac is None:
            return None
         
        key=ip+"_"+mac

        if self.arp_table.has_key(key):
            return self.arp_table[ key ]
        
        return None
        
    def clean_stale_arp(self,keep_days=180):
        "Clean up ARP entries older than keep_days. Also checks against include/exlude lists"


        # datetime could be used here for more accurate date
        # arithmetic but for these purposes it isn't necessary; just
        # simple epoch delta will do

        current_time=int(time.time())
        time_delta=keep_days*24*math.pow(60,2)
        oldest_allowed=current_time-time_delta

        ArpWatchLogging.log_message(syslog.LOG_NOTICE,
                                    "Cleaning up ARP entries older than %s" %
                                    (time.strftime("%F %X %Z",time.gmtime(oldest_allowed))))
        
        new_table=dict()
        remove_count=0
        
        for entry in self.arp_table.values():

            if ( self.ip_address_included(entry.ip) and
                 self.mac_address_included(entry.mac) and
                 entry.epoch > oldest_allowed):
                new_table[entry.hash_key()]=entry
            else:
                remove_count+=1

        ArpWatchLogging.log_message(syslog.LOG_NOTICE,"%d entries removed" % remove_count)
        
        self.arp_table=new_table

    def include_mac_address(self,pattern):
        if self.include_macaddr is None:
            self.include_macaddr=[]

        self.include_macaddr.append(re.compile(pattern))
    
    def exclude_mac_address(self,pattern):
        if self.exclude_macaddr is None:
            self.exclude_macaddr=[]

        self.exclude_macaddr.append(re.compile(pattern))
    
    def include_ip_address(self,pattern):
        if self.include_ipaddr is None:
            self.include_ipaddr=[]

        self.include_ipaddr.append(re.compile(pattern))
    
    def exclude_ip_address(self,pattern):
        if self.exclude_ipaddr is None:
            self.exclude_ipaddr=[]

        self.exclude_ipaddr.append(re.compile(pattern))
    
    def ip_address_included(self,address):
        if address is None:
            return False
        
        if self.include_ipaddr is not None:
            for pattern in self.include_ipaddr:
                if pattern.match(address):
                    return True
        
        if self.exclude_ipaddr is not None:
            for pattern in self.exclude_ipaddr:
                if pattern.match(address):
                    return False
        
        return True

    def mac_address_included(self,mac):

        if mac is None:
            return False
        
        if self.include_macaddr is not None:
            for pattern in self.include_macaddr:
                if pattern.match(mac):
                    return True
        
        if self.exclude_macaddr is not None:
            for pattern in self.exclude_macaddr:
                if pattern.match(mac):
                    return False
         
        return True
        
        
        
