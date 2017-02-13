#!/usr/bin/env python
# Copyright (c) 2016 Nagios Enterprises
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: A handy description goes here
# 
# Author:
#  Nagios Enterprises
#  Matthew Capra
# -- ref https://github.com/CoreSecurity/impacket/blob/master/examples/wmiquery.py

import argparse
import sys
import os
import logging
import time

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_NONE

#------------------------------------------------------------------------------------------------
def checkcpu(shell):
	nagios_exit = {}
	set1 = shell.onecmd('select PercentProcessorTime,Timestamp_Sys100NS from Win32_PerfRawData_PerfOS_Processor where Name="_Total";')
	
	time.sleep(2)
	set2 = shell.onecmd('select PercentProcessorTime,Timestamp_Sys100NS from Win32_PerfRawData_PerfOS_Processor where Name="_Total";')
	if(args.verbose):
		for p in set2:
			print(p)
		for p in set1:
			print(p)

	value = float((1-((float(set2[0]['PercentProcessorTime'] - set1[0]['PercentProcessorTime'])) / (float(set2[0]['Timestamp_Sys100NS'] - set1[0]['Timestamp_Sys100NS'])))) * 100)
	if value < 0:
		value = 0
	value = float("{0:.2f}".format(value))
	
	if ((args.critical is not None) and (value >= float(args.critical))):
		nagios_exit['status'] = str('CRITICAL - CPU usage is ' + str(value) + '%|\'usage\'=' + str(value) + '%')
		nagios_exit['code'] = int(2)
	elif ((args.warning is not None) and (value >= float(args.warning))):
		nagios_exit['status'] = str('WARNING - CPU usage is ' + str(value) + '%|\'usage\'=' + str(value) + '%')
		nagios_exit['code'] = int(1)
	else:
		nagios_exit['status'] = str('OK - CPU usage is ' + str(value) + '%|\'usage\'=' + str(value) + '%')
		nagios_exit['code'] = int(0)
			
	return nagios_exit
#------------------------------------------------------------------------------------------------
def checkdrivesize(shell):
	nagios_exit = {}
	if(args.label is None):
		nagios_exit['status'] = str('UNKNOWN - You must provide a drive (--label).')
		nagios_exit['code'] = int(3)
	else:
		set = shell.onecmd('Select DeviceID,freespace,Size,VolumeName from Win32_LogicalDisk where DriveType=3;')
		for el in set:
			print el['Device']['value']
		print 
		nagios_exit = {}
		nagios_exit['status'] = str('UNKNOWN - Not yet implemented.')
		nagios_exit['code'] = int(3)
	
	return nagios_exit
#------------------------------------------------------------------------------------------------






if __name__ == '__main__':
	import cmd
	
	parser = argparse.ArgumentParser(add_help = True, description = "Executes WQL queries and gets object descriptions using Windows Management Instrumentation.")

	parser.add_argument('-H', '--host', action='store', help='The host name or logical address of the remote Windows machine.', required=True)
	parser.add_argument('-u', '--username', action='store', help='The host name or logical address of the remote Windows machine.', required=True)
	parser.add_argument('-p', '--password', action='store', help='The host name or logical address of the remote Windows machine.', required=True)
	parser.add_argument('-C', '--command', action='store', help='The sub-command you wish to run. Currently only \'checkcpu\' is valid.', required=True)
	parser.add_argument('-v', '--verbose', action='store_true', help='Print extra debug information. Don\'t include this in your check_command definition!', default=False)
	parser.add_argument('-w', '--warning', action='store', help='The warning threshold for the check. See commands for individual usage.', default=None)
	parser.add_argument('-c', '--critical', action='store', help='The critical threshold for the check. See commands for individual usage.', default=None)
	parser.add_argument('-l', '--label', action='store', help='The label for the drive you want to check (C, E, etc).')
	
	args = parser.parse_args()

	class WMIQUERY(cmd.Cmd):
		def __init__(self, iWbemServices):
			cmd.Cmd.__init__(self)
			self.iWbemServices = iWbemServices
			self.prompt = 'WQL> '
			self.intro = '[!] Press help for extra shell commands'

		def do_help(self, line):
			print """
	 lcd {path}					- changes the current local directory to {path}
	 exit						- terminates the server process (and this session)
	 describe {class}			- describes class
	 ! {cmd}					- executes a local shell cmd
	 """ 

		def do_shell(self, s):
			os.system(s)

		def do_describe(self, sClass):
			sClass = sClass.strip('\n')
			if sClass[-1:] == ';':
				sClass = sClass[:-1]
			try:
				iObject, _ = self.iWbemServices.GetObject(sClass)
				iObject.printInformation()
				iObject.RemRelease()
			except Exception, e:
				#import traceback
				#print traceback.print_exc()
				logging.error(str(e))

		def do_lcd(self, s):
			if s == '':
				print os.getcwd()
			else:
				os.chdir(s)
	
		def printReply(self, iEnum):
			printHeader = True
			while True:
				try:
					pEnum = iEnum.Next(0xffffffff,1)[0]
					record = pEnum.getProperties()
					if printHeader is True:
						print '|', 
						for col in record:
							print '%s |' % col,
						print
						printHeader = False
					print '|', 
					for key in record:
						print '%s |' % record[key]['value'],
					print 
				except Exception, e:
					#import traceback
					#print traceback.print_exc()
					if str(e).find('S_FALSE') < 0:
						raise
					else:
						break

		def default(self, line):
			line = line.strip('\n')
			if line[-1:] == ';':
				line = line[:-1]
			try:
				iEnumWbemClassObject = self.iWbemServices.ExecQuery(line.strip('\n'))
				ret = []
				while True:
					try:
						pEnum = iEnumWbemClassObject.Next(0xffffffff,1)[0]
						record = pEnum.getProperties()
						temp = {}
						for key in record:
							temp[key] = record[key]['value']
						ret.append(temp)
					except Exception, e:
						if str(e).find('S_FALSE') < 0:
							raise
						else:
							break
				#ret = pEnum.getProperties()
				iEnumWbemClassObject.RemRelease()
				return ret
			except Exception, e:
				logging.error(str(e))
		 
		def emptyline(self):
			pass

		def do_exit(self, line):
			return True

	try:
		dcom = DCOMConnection(args.host, args.username, args.password, "", "", "", "", oxidResolver=True,doKerberos=False, kdcHost="")

		iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
		iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
		iWbemServices= iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
		
		iWbemLevel1Login.RemRelease()
		shell = WMIQUERY(iWbemServices)
		
		nagios_exit = {}

		if args.command == 'checkcpu':
			nagios_exit = checkcpu(shell)
		elif args.command == 'checkdrivesize':
			nagios_exit = checkdrivesize(shell)
		else:
			nagios_exit['status'] = 'UNKNOWN - command \'' + args.command + '\' not found.'
			nagios_exit['code']=3;
		
		iWbemServices.RemRelease()
		dcom.disconnect()
		# todo exit with code and status message
		print(nagios_exit['status'])
		exit(nagios_exit['code'])
		
	except Exception, e:
		logging.error(str(e))
		try:
			dcom.disconnect()
		except:
			pass
