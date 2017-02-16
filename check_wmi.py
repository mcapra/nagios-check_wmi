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
		nagios_exit['perfdata'] = '|\'usage\'=' + str(value) + '%'
		nagios_exit['code'] = int(2)
	elif ((args.warning is not None) and (value >= float(args.warning))):
		nagios_exit['status'] = str('WARNING - CPU usage is ' + str(value) + '%|\'usage\'=' + str(value) + '%')
		nagios_exit['perfdata'] = '|\'usage\'=' + str(value) + '%'
		nagios_exit['code'] = int(1)
	else:
		nagios_exit['status'] = str('OK - CPU usage is ' + str(value) + '%')
		nagios_exit['perfdata'] = '|\'usage\'=' + str(value) + '%'
		nagios_exit['code'] = int(0)
			
	return nagios_exit
#------------------------------------------------------------------------------------------------
def checkdrivesize(shell):
	nagios_exit = {}
	list = []
	drives = []
	key = 'DeviceID'
	uom = args.unit
	scalar = {}
	scalar['kB'] = float(args.bytefactor / args.bytefactor / args.bytefactor )
	scalar['MB'] = float(args.bytefactor / args.bytefactor / args.bytefactor / args.bytefactor )
	scalar['GB'] = float(args.bytefactor / args.bytefactor / args.bytefactor / args.bytefactor / args.bytefactor)
	
	warning_count = 0
	critical_count = 0
	raw_count = 0
	
	set = shell.onecmd('Select DeviceID,freespace,Size,VolumeName from Win32_LogicalDisk where DriveType=3;')
	
	if not set: # no drives found in set, unknown?
		nagios_exit['status'] = str('UNKNOWN - Could not detect any drives on the Windows machine.')
		nagios_exit['code'] = int(3)
		nagios_exit['perfdata'] = ''
		return nagios_exit

	if(not ((args.label is not None) and (args.name is not None))):
		nagios_exit['perfdata'] = '|'
		if(args.label is not None):
			key = 'DeviceID'
			if(args.label.find(',') != -1): # list is labels
				list = args.label.split(',')
			else:
				list = [args.label]
		elif(args.name is not None): # list is names
			key = 'VolumeName'
			if(args.name.find(',') != -1):
				list = args.name.split(',')
			else:
				list = [args.name]
				
		if not list: # list is not set, check all drives and return
			for p in set:
				raw_count += 1
				
				if(uom == '%'):
					value = float((float(p['FreeSpace']) / float(p['Size'])) * 100)
				else:
					value = (float(p['FreeSpace'])) * scalar[uom]
				
				#build perfdata
				nagios_exit['perfdata'] += '\'' + p[key] + '_freespace\'=' + str(float("{0:.2f}".format(value))) + uom + ';'
				
				if (args.warning is not None):
					nagios_exit['perfdata'] += args.warning + ';'
					if (value <= float(args.warning)):
						drives.append(p[key])
						warning_count += 1
				else:
					nagios_exit['perfdata'] += ';'
					
				if (args.critical is not None):
					nagios_exit['perfdata'] += args.critical + ';'
					if(value <= float(args.critical)):
						drives.append(p[key])
						critical_count += 1
				else:
					nagios_exit['perfdata'] += ';'
				nagios_exit['perfdata'] += ' '
		else: # have a list, do it up
			for p in set:
				if(p[key] in list):
					raw_count += 1
					
					if(uom == '%'):
						value = float((float(p['FreeSpace']) / float(p['Size'])) * 100)
					else:
						value = (float(p['FreeSpace'])) * scalar[uom]
				
					#build perfdata
					nagios_exit['perfdata'] += '\'' + p[key] + '_freespace\'=' + str(float("{0:.2f}".format(value))) + uom + ';'
					
					if (args.warning is not None):
						nagios_exit['perfdata'] += args.warning + ';'
						if (value <= float(args.warning)):
							drives.append(p[key])
							warning_count += 1
					else:
						nagios_exit['perfdata'] += ';'
						
					if (args.critical is not None):
						nagios_exit['perfdata'] += args.critical + ';'
						if(value <= float(args.critical)):
							drives.append(p[key])
							critical_count += 1
					else:
						nagios_exit['perfdata'] += ';'
					nagios_exit['perfdata'] += ' '
		
		if(raw_count > 0):	
			if(critical_count > 0):
				nagios_exit['status'] = str('CRITICAL - Found problems on the following drive(s): ' + str(drives) + '.')
				nagios_exit['code'] = int(2)
			elif(warning_count > 0):
				nagios_exit['status'] = str('WARNING - Found problems on the following drive(s): ' + str(drives) + '.')
				nagios_exit['code'] = int(1)
			else:
				nagios_exit['status'] = str('OK - Found NO problems on any provided drives.')
				nagios_exit['code'] = int(0)
			return nagios_exit
		else:
			nagios_exit['status'] = str('UNKNOWN - Couldn\'t find the listed drive(s): ' + str(list) + '.')
			nagios_exit['code'] = int(3)
			nagios_exit['perfdata'] = ''
			return nagios_exit
	else: # violates xor of label+name
		nagios_exit['status'] = str('UNKNOWN - You can\'t use both -l/--label and -n/--name for checkdrivesize! Please use one or the other!')
		nagios_exit['code'] = int(3)
		nagios_exit['perfdata'] = ''
		return nagios_exit

	return nagios_exit
#------------------------------------------------------------------------------------------------






if __name__ == '__main__':
	import cmd
	
	parser = argparse.ArgumentParser(add_help = True, description = "Executes WQL queries and gets object descriptions using Windows Management Instrumentation.")

	parser.add_argument('-H', '--host', action='store', help='The host name or logical address of the remote Windows machine.', required=True)
	parser.add_argument('-u', '--username', action='store', help='The host name or logical address of the remote Windows machine.', required=True)
	parser.add_argument('-p', '--password', action='store', help='The host name or logical address of the remote Windows machine.', required=True)
	parser.add_argument('-v', '--verbose', action='store_true', help='Print extra debug information. Don\'t include this in your check_command definition!', default=False)
	
	subparsers = parser.add_subparsers(help='sub-command help', dest='command')
	
	parser_checkcpu = subparsers.add_parser('checkcpu', help='a help')
	parser_checkcpu.add_argument('-w', '--warning', action='store', help='The warning threshold for the check in percent CPU used. (Example: -w 20)', default=None)
	parser_checkcpu.add_argument('-c', '--critical', action='store', help='The critical threshold for the check in in percent CPU used. (Example: -c 40)', default=None)
	
	parser_checkdrivesize = subparsers.add_parser('checkdrivesize', help='a help')
	parser_checkdrivesize.add_argument('-w', '--warning', action='store', help='The warning threshold for the check in terms of free space remaining. Meaning is derived from the unit (-u/--unit) used.', default=None)
	parser_checkdrivesize.add_argument('-c', '--critical', action='store', help='The critical threshold for the check in terms of free space remaining. Meaning is derived from the unit (-u/--unit) used.', default=None)
	parser_checkdrivesize.add_argument('-U', '--unit', action='store', help='The unit of meansurement used. Defaults to percentage.', choices=['%','GB','MB','kB'], default='%')
	parser_checkdrivesize.add_argument('-B', '--bytefactor', action='store', help='The bytefactor is either 1000 or 1024 and is used for conversion units eg bytes to GB. Default is 1024.', choices=[1000.0,1024.0], default=1024.0)
	parser_checkdrivesize.add_argument('-l', '--label', action='store', help='The label for the drive you want to check (C:, E:, etc). Can support comma-separated list. Example: --label C:,E:,G: or --label C:')
	parser_checkdrivesize.add_argument('-n', '--name', action='store', help='The name for the drive you want to check (TEAMSHARE, ntfs_share, etc). Can support comma-separated list. Example: -n \'TEAMSHARE\' or --name \'TEAMSHARE,ntfs_share,backup\'.')
	
	
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
		
		if (args.command == 'checkcpu'):
			nagios_exit = checkcpu(shell)
		elif (args.command == 'checkdrivesize'):
			nagios_exit = checkdrivesize(shell)
		else:
			nagios_exit['status'] = 'UNKNOWN - command \'' + args.command + '\' not found.'
			nagios_exit['perfdata'] = ''
			nagios_exit['code']=3;
		
		iWbemServices.RemRelease()
		dcom.disconnect()

		print(nagios_exit['status'] + nagios_exit['perfdata'])
		exit(nagios_exit['code'])
		
	except Exception, e:
		logging.error(str(e))
		try:
			dcom.disconnect()
		except:
			pass
