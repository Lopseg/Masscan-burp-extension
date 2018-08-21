# DEVELOPED BY RAFAEL RODRIGUES DA SILVA 08/20/2018

from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList
from java.net import URL

import subprocess
import threading
import re
import time

# IP PATTERN TO FILTER IP ADDRESS
ip_pattern = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
ip_pattern = re.compile(ip_pattern)


class BurpExtender(IBurpExtender, IContextMenuFactory):
  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers   = callbacks.getHelpers()
    self.context    = None

    # we set up our extension
    callbacks.setExtensionName("BHP Port scan")
    callbacks.registerContextMenuFactory(self)

    return

  def createMenuItems(self, context_menu):
    self.context = context_menu
    menu_list = ArrayList()
    menu_list.add(JMenuItem("Send to Port scanner", actionPerformed=self.pre_scan))

    return menu_list


  def start_scan(self,host):

    nslookup = 'dig +short '+host
    # retrieve ip address of a subdomain
    cmd = subprocess.Popen(nslookup,shell=True,stdin=subprocess.PIPE,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
    dig_output = cmd.stdout.read()

    print 'Checking if dig found the correct ip address\n'
    print dig_output

    # for each ipadress, send to masscan one-by-one, scan it, save the output to a specific file, show the output and show where is the output file of each ipadress
    for i in dig_output.split('\n'):
        is_ip = re.match(ip_pattern,i)

        if is_ip:

            print 'ip %s found lets scan'%i
            masscan = 'masscan --max-rate 1000 -p 1-65535 '+i+' > output.'+i

            cmd = subprocess.Popen(masscan,shell=True,stdin=subprocess.PIPE,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
            nop =  cmd.stdout.read() # we are saving this value in a variable just to make sure that the masscan has finished before burp reads the file

            print '\nRESULTS:'

            cmd = subprocess.Popen('cat output.'+i,shell=True,stdin=subprocess.PIPE,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
            print cmd.stdout.read()
            print cmd.stderr.read()

            print 'Output file is located at:\n'

            cmd = subprocess.Popen('readlink -f output.'+i,shell=True,stdin=subprocess.PIPE,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
            print cmd.stdout.read()
            print cmd.stderr.read()

    return

  def pre_scan(self,event):

    # grab the details of what the user clicked
    http_traffic = self.context.getSelectedMessages()

    print "%d requests highlighted" % len(http_traffic)

    for traffic in http_traffic:

      http_service = traffic.getHttpService()
      host         = http_service.getHost()

      print "User selected host: %s" % host

      t = threading.Thread(target=self.start_scan,args=(host,))
      t.start()

      return
