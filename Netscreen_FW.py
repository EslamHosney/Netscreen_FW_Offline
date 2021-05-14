# -*- coding: utf-8 -*-
"""
Created on Thu Sep 20 14:35:39 2018

@author: V17IAhmed36
"""
import netaddr
import datetime
from Firewall import Firewall, ReadFile, WriteFile

class Netscreen(Firewall):
    
    def __init__(self,name,ip,username,password,configFile,routeFile):
        Firewall.__init__(self, name,ip,username,password,configFile,routeFile)
        self.type = "Netscreen"
        self.routeTable = self.getRouteTable()
        
class Netscreen(Firewall):
    
    def __init__(self,name,ip,username,password,configFile,routeFile):
        Firewall.__init__(self, name,ip,username,password,configFile,routeFile)
        self.type = "Netscreen"
        self.routeTable = self.getRouteTable()
## Not migrated to main code        
    def getRouteTable(self):
        #Iterates through the Route file and return routeing table
        lineIndex = 0
        routeTable = {}
        while(lineIndex < len(self.routeFile)):
            buff = self.routeFile[lineIndex].split()
            if (len(buff) < 4):
                lineIndex += 1
                continue
            elif(buff[0] != "*"):
                address = buff[1].split('/')[0]
#                
                if (netaddr.valid_ipv4(buff[1].split('/')) ):
                    nextHopInterface = buff.split()[2]
                    if (not nextHopInterface == 'n/a'):
                        routeTable[netaddr.IPNetwork(buff[1])] = buff.split()[2]
                        lineIndex += 1
                        continue    
            address = buff[2].split('/')[0]
            
            if (netaddr.valid_ipv4(address)):
                nextHopInterface = buff[3]
                if (not nextHopInterface == 'n/a'):
                    routeTable[netaddr.IPNetwork(buff[2])] = buff[3]   
            lineIndex += 1
            continue
#        for key in routeTable.keys():
#            print key,routeTable[key]
#        raw_input("continue")
        return routeTable

    
    def getRouteInterface(self,IP):
        #return the route Interface for a subnet and returns None if no route found even default, IP in netaddr IPv4 Network
        bestMatchInterface = None
        bestMatchSubnet = netaddr.IPNetwork("0.0.0.0/0")
        #print bestMatchSubnet.size
        #print IP in bestMatchSubnet
#        bestMatchSize = bestMatchSubnet.size
        for subnet, interface in self.routeTable.iteritems():
            #print (subnet, interface)
            if ((IP in subnet) and (subnet.size <= bestMatchSubnet.size) and (interface != 'n/a')):
                #print "Route"
                bestMatchInterface = interface
                bestMatchSubnet = subnet
#                bestMatchSize = subnet.size
        #print bestMatchInterface
        return bestMatchInterface
    
    def getIPZone(self,IP):
        #get routeInterface for IP and check the configFile for the Zone for this interface retun Zone
        interface = self.getRouteInterface(IP)
        #print ("Here", interface)
        zone = None
        if (interface == None):
            raise ValueError('No route found for this IP "'+str(IP)+'"! please add route to the '+self.name+'_routes file and try again')
        for line in self.configFile:
            if (line.find("set interface ") != -1 ) and ("zone" in line):
#                if ( (interface[:3] in line) and (interface[3:] in line)):#interface name in route file in eth but in config file ethernet
                if ( ('"ethernet'+interface[3:]+'"' in line)):
                    zone = line.split('"')[-2]
        #return "Trust"
        return zone
    
    def getAddressNames(self,zone,IP):
        #return addressNames
        addressNames = []
        for line in self.configFile:
            if (line.find('set address "'+zone+'" ') != -1 ):
                if  (line.split()[-2] == str(IP.ip)) and (line.split()[-1] == str(IP.netmask)):
                    addressNames.append(line.split('"')[-2])
        return addressNames
#        pass
    
    def createAddress(self,addressName,zone,IP):
        #return config for address
        line = 'set address "'+zone+'" "'+addressName+'" '+str(IP.ip)+" "+str(IP.netmask)
        self.createdConfig.append(line)
        self.configFile.append(line)
        WriteFile(self.name,['\n',line])
        pass
    
    def getAppNames(self,startPort,endPort,protocol,appNameDefined=None):
        #return appNames
        if(startPort == endPort == protocol):
            return protocol
        appName = None
        for line in self.configFile:
            if (line.find('set service ') != -1 and line.find("protocol") != -1):
                if(line.find(protocol) != -1 and line.find(" "+startPort+'-'+endPort) != -1):
                    return line.split('"')[1]
        return appName
    
    def createApp(self,startPort,endPort,protocol,appName=None):
        #return app config
        #set service "TCP 2022-2024" protocol tcp src-port 0-65535 dst-port 2022-2024
        if (not appName):
            if (startPort == endPort):
                appName = protocol.upper()+"_"+startPort
            else:
                appName = protocol.upper()+"_"+startPort+"-"+endPort
                
        lines = ['set service "'+appName+'" protocol '+protocol+" src-port 0-65535 dst-port "+startPort+"-"+endPort]
        self.createdConfig += lines
        self.configFile += lines
        WriteFile(self.name,lines)
        return appName        
        
    
    def createPolicy(self,policyName,sourceZone,sourceAddressNames,destinationZone,destinationAddressNames,appNames):
        
        lines = []
        lines.append('set policy top name "'+policyName+'" from "'+sourceZone+'" to "'+destinationZone+'" "'+sourceAddressNames[0]+'" "'+destinationAddressNames[0]+'" "'+appNames[0]+'" permit log')
        lines.append('set policy id XXX')
        for sourceAddress in sourceAddressNames[1:]:
            lines.append('set src-address "'+sourceAddress+'"')
        for destinationAddress in destinationAddressNames[1:]:
            lines.append('set dst-address "'+destinationAddress+'"')            
        for appName in appNames[1:]:
            lines.append('set service "'+appName+'"')
        lines.append('exit')
        self.createdConfig += lines
        self.configFile += lines
        WriteFile(self.name,lines)        
        return

    def getAddressesSameIPZone(self):
        #return groups of dupliate addresses with the same IP and zone
        duplicateIPNames = []
        alreadyCheckedIPs = []
        print('Get Duplicate Addresses: '),
        for line in self.configFile:
            print('!'),
            if (line.find('set address ') != -1):
                if (netaddr.valid_ipv4((line.split()[-2])) and netaddr.valid_ipv4(line.split()[-1])):  #check if ip address not pc name
                    IPStr = line.split()[-2] + "/"+ line.split()[-1]
                    if (not IPStr in alreadyCheckedIPs):
                        alreadyCheckedIPs.append(IPStr)
                        IP = netaddr.IPNetwork(IPStr)
                        zone = line.split('"')[1]
                        addressNamesInZone = self.getAddressNames(zone, IP)    
                        if (len(addressNamesInZone) > 1):
                            duplicateIPNames.append([IP,zone,addressNamesInZone])
        
        return duplicateIPNames


    #################Specific for Netscreen##########################################################################################
    def getPolicyWithWord(self,word):
        #returns policy with specific word ex "set policy id 25" 
        out = []
        lineIndex = 0
        while (lineIndex < len(self.configFile)):
            if (self.configFile[lineIndex].find(word) != -1 and self.configFile[lineIndex].find("set policy") != -1):
                while(not self.configFile[lineIndex] == "exit"):
                    out.append(self.configFile[lineIndex])
                    lineIndex += 1  
                out.append("exit")
            lineIndex += 1
        return out
    
    def getIPwithAddress(self,word):
        out = []
        lineIndex = 0
        while (lineIndex < len(self.configFile)):
            if (self.configFile[lineIndex].find(word) != -1 and (self.configFile[lineIndex].find("set address") != -1 or self.configFile[lineIndex].find("set group address") != -1)):#set group address
                out.append(self.configFile[lineIndex])
            lineIndex += 1
        return out
    
    def getExpiredSchedulers(self):
        #returns the names of all expired schedulers, what the heck is recurrent scheduler
        expiredSchedulers = []
#        import datetime
#        
#        date_time_str = '2018-06-29 08:15:27.243860'  
#        date_time_obj = datetime.datetime.strptime(date_time_str, '%Y-%m-%d %H:%M:%S.%f')
        for line in self.configFile:
            #for each line in configfile
            endDate = ""
            if (line.find('set scheduler ') != -1 and line.find(" start ") != -1 and line.find(" stop ") != -1 and line.find(" recurrent ") == -1):
                #if it's a scheduler line withour recurrent
                endDate = datetime.datetime.strptime(line.split('"')[2].split()[5], '%m/%d/%Y') # create endDate object
                if (endDate < datetime.datetime.now()): # if date earlier than today add to list
                    schedulerName = line.split('"')[1]
                    expiredSchedulers.append(schedulerName)
#                    print (schedulerName, endDate)
        
        return expiredSchedulers
    
    def parseServices(self):
        #return a dictionary with the service name as key and value = list of list [protocol,startPort,endPort] if len > 1 should be port group
        servicesDict = {}
        lineIndex = 0
        while (lineIndex < len(self.configFile)):
            if (self.configFile[lineIndex].find("set service ") != -1 and self.configFile[lineIndex].find(" src-port ") != -1):
                serviceName = self.configFile[lineIndex].split('"')[1]
                print serviceName
#                print self.configFile[lineIndex]
                startPort, endPort = self.configFile[lineIndex].split(" dst-port ")[1].split(" ")[0].split("-")
                
                if (self.configFile[lineIndex].find(" udp src-port ") != -1):
                    protocol = "udp"
                elif (self.configFile[lineIndex].find(" tcp src-port ") != -1):
                    protocol = "tcp"
                else:
                    print "check "+ self.configFile[lineIndex]
                           
                if (not serviceName in servicesDict.keys()):
                    servicesDict[serviceName] = [[protocol, startPort, endPort]]
                else:
                    servicesDict[serviceName].append([protocol, startPort, endPort])
            lineIndex += 1
        return servicesDict
 
if __name__ == "__main__":
    ip = netaddr.IPNetwork('10.230.99.172')
#    print (str(ip))
    f = Netscreen("","","","",ReadFile('SF.txt'),ReadFile('SF_routes.txt'))               
        