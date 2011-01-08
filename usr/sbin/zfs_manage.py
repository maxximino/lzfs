#!/usr/bin/python
import os
import sys
import md5
import dbus
import getopt
import string
import commands 
import dmidecode
import gettext
_ = gettext.gettext

import xml.etree.cElementTree as ElementTree

# test argument
#args = '-u myasduser --user=masdyuser -p mypaadfss --password=mypaasdfss -k serasdasdialkey --key=serasdfialkey -s myservasdfer --server=masdfyserver --unregister --help'.split()

ZFS_SERIAL      = '/etc/zfs/zfs_serial'
ZFS_CONFIG      = '/etc/zfs/zfs_config'

class XmlDictConfig(dict):
    def __init__(self, aDict):
        bDict = {}
        for element in aDict:
            if element:
                if len(element) == 1 or element[0].tag != element[1].tag:
                    bDict = {element.tag: XmlDictConfig(element)}
                else:
                    bDict = {element[0].tag : XmlDictConfig(element)}
                if element.items():
                    bDict.update(dict(element.items()))
            elif element.items():
                bDict.update({element.tag: dict(element.items())})
            else:
                bDict.update({element.tag: element.text})
        self.update(bDict)


class XmlParser():
    def xmlToDict(self, parent_element):
        aDict = {}
        if parent_element.items():
            aDict.update(dict(parent_element.items()))
        for element in parent_element:
            if element:
                if len(element) == 1 or element[0].tag != element[1].tag:
                    bDict = XmlDictConfig(element)
                else:
                    bDict = {element[0].tag: XmlDictConfig(element)}
                if element.items():
                    bDict.update(dict(element.items()))
                aDict.update({element.tag: bDict})
            elif element.items():
                aDict.update({element.tag: dict(element.items())})
            else:
                aDict.update({element.tag: element.text})
        return aDict
    
    def dictToXml(self, aDict):
        elem = ElementTree.Element("context")
        for key, value in aDict.items():
            if isinstance(value, type(0)):
                ElementTree.SubElement(elem, key, type="int").text = str(value)
            elif isinstance(value, dict):
                test = self.dictToString(ElementTree.Element(key), value)
                ElementTree.SubElement(elem, key).text = test
            else:
                ElementTree.SubElement(elem, key).text = value
        dictAsXML = ElementTree.tostring(elem)
        dictAsXML = dictAsXML.replace("&lt;", "<")
        dictAsXML = dictAsXML.replace("&gt;",">")
        return dictAsXML
        
    def dictToString(self, elem, aDict):
        aList=[]
        for key, value in aDict.items():
            if isinstance(value, type(0)):
                ElementTree.SubElement(elem, key, type="int").text = str(value)
            elif isinstance(value, dict):
                print "Element is a dict"
                ElementTree.SubElement(elem, key).text = self.dictToString(key, value)
            else:
                ElementTree.SubElement(elem, key).text = value
                aList.append("<" + key + ">" + value + "</" + key + ">")
        return ''.join(aList)
 
# this does not change, we can cache it
_dmi_data           = None
_dmi_not_available = 0

def dmi_warnings():
    if not hasattr(dmidecode, 'get_warnings'):
        return None

    return dmidecode.get_warnings()

def _initialize_dmi_data():
    """ Initialize _dmi_data unless it already exist and returns it """
    global _dmi_data, _dmi_not_available
    if _dmi_data is None:
        if _dmi_not_available:
            # do not try to initialize it again and again if not available
            return None
        else :
            dmixml = dmidecode.dmidecodeXML()
            dmixml.SetResultType(dmidecode.DMIXML_DOC)
            # Get all the DMI data and prepare a XPath context
            try:
                data = dmixml.QuerySection('all')
                dmi_warn = dmi_warnings()
                if dmi_warn:
                    dmidecode.clear_warnings()
                    log = up2dateLog.initLog()
                    log.log_debug("dmidecode warnings: " % dmi_warn)
            except:
                # DMI decode FAIL, this can happend e.g in PV guest
                _dmi_not_available = 1
                dmi_warn = dmi_warnings()
                if dmi_warn:
                    dmidecode.clear_warnings()
                return None
            _dmi_data = data.xpathNewContext();
    return _dmi_data

def get_dmi_data(path):
    """ Fetch DMI data from given section using given path.
        If data could not be retrieved, returns empty string.
        General method and should not be used outside of this module.
    """
    dmi_data = _initialize_dmi_data()
    if dmi_data is None:
       return ''
    data = dmi_data.xpathEval(path)
    if data != []:
        return data[0].content
    else:
        # The path do not exist
        return ''

def dmi_system_uuid():
    """ Return UUID from dmidecode system information.
        If this value could not be fetch, returns empty string.
    """
    # if guest was created manualy it can have empty UUID, in this
    # case dmidecode set attribute unavailable to 1
    uuid = get_dmi_data("/dmidecode/SystemInfo/SystemUUID[not(@unavailable='2')]")
    if not uuid:
        uuid = ''
    return uuid


def get_smbios():
    """ Returns dictionary with values we are interested for.
        For historical reason it is in format, which use HAL.
        Currently in dictionary are keys:
        smbios.system.uuid, smbios.bios.vendor, smbios.system.serial,
        smbios.system.manufacturer.
    """
    _initialize_dmi_data()
    if _dmi_not_available:
        return {}
    else:
        return {
            'smbios.system.uuid': dmi_system_uuid(),
            'smbios.bios.vendor': get_dmi_data('/dmidecode/BIOSinfo/Vendor'),
            'smbios.system.serial': get_dmi_data('/dmidecode/SystemInfo/SerialNumber'),
            'smbios.system.manufacturer': get_dmi_data('/dmidecode/BaseBoardInfo/Manufacturer'),
            'smbios.system.product': get_dmi_data('/dmidecode/SystemInfo/ProductName'),
        }

def usage():
        print "\nUsage is:\n "
        print sys.argv[0] + ' -u <username> --user=<username> -p <password> --password=<password> -k <serialkey> --key=<serialkey> -s <server> --server=<server> -o <operation> --operation=<operation> --help --dumpxml'
        print "\n<operation> => register , unregister, support (default is register)\n"
        print "Mandatory field(s)* (always)                 : user, password"
        print "Mandatory field(s)* (first time registration) : key\n"
        sys.exit(-1)
 

def main():
    if len(sys.argv) == 1 :
        usage()

    index = -1
    try :
        index = sys.argv.index("--help")
    except:
        print
    if index != -1:
        usage()

    zfs_config     = {"user":"",
                      "password":"",
                      "key":"",
                      "server":"",
                      "operation":"register",
                      "help":"",
                      "dumpxml":""}
    opt_zfs_config = {"-u":"user","--user":"user",
                      "-p":"password", "--password":"password",
                      "-k":"key", "--key":"key",
                      "-s":"server","--server":"server",
                      "-o":"operation","--operation":"operation",
                      "--help":"help",
                      "--dumpxml":"dumpxml"}
 
    # get default serial
    try:
        fd = open(ZFS_SERIAL)
        zfs_config['key'] = fd.read()
        fd.close()
    except:
        print

    optlist, args = getopt.gnu_getopt(sys.argv, 'dhu:p:k:s:o:n:',["user=", "password=", "key=", "server=", "operation=","unregister", "help","dumpxml"])
    for ele in optlist:
        zfs_config[opt_zfs_config[ele[0]]] = ele[1]
    # set md5 checksum of password as password
    zfs_config['password'] = md5.md5(zfs_config['password']).hexdigest()

    if zfs_config['user'] == '' or zfs_config['password'] == '' or zfs_config['key'] == '' :
        print "Mandatory fields are must. Please provide mendatory information."
        exit(-1)

    import SOAPpy

    ns = 'http://tempuri.org/KQInfotech'
    # default web service url ( currently using test url)
    url = 'http://192.168.1.175/ZFS.KQInfotech.WebService/UserMachineDetailsService.asmx'

    # chekc for web service url in configuration file
    confdict = {}
    try :
        fd = open(ZFS_CONFIG)
        data = fd.read()
        fd.close()
        sdata = data.split()
        for i in sdata:
            tmp = i.split('=')
            confdict[tmp[0]] =  tmp[1]
    except :
        print 
    # override dafault web service url if its available and is not empty
    if confdict.get('server') != None:
        if confdict['server'] != '':
            url = confdict['server']

    server = SOAPpy.SOAPProxy( url, namespace=ns )
    server.config.buildWithNamespacePrefix = 0

    # remove unnecessary option from zfs_config
    zfs_config.pop('dumpxml')
    zfs_config.pop('help')
    zfs_config.pop('server')
    zfs_config["machine"] = get_smbios()

    if zfs_config['operation'] == 'support' :
        try:
            # generate xml for zfs user registration info
            xmldata= XmlParser().dictToXml(zfs_config)
            fd = open("/tmp/dumpInfo.xml","w")
            fd.write(xmldata)
            fd.close()
            ret = commands.getstatusoutput("SystemReport.sh")
            if ret[0] != 0 :
                print "sysreport generation failed"
            print "please send email to 'support@kqinfotech.com' with subject 'support' and attachment files '/tmp/dumpInfo.xml' and '/tmp/SysReport.tar.gz'"
            return 
        except:
            print "error occured : support ops"
            sys.exit(-1)

    if zfs_config['operation'] == 'unregister' :
        try:
            # generate xml for zfs user registration info
            xmldata= XmlParser().dictToXml(zfs_config)
            fd = open("/tmp/dumpInfo.xml","w")
            fd.write(xmldata)
            fd.close()
            print "please send email to 'support@kqinfotech.com' with subject 'unregister' and attachment file '/tmp/dumpInfo.xml' "
            return 
        except:
            print "No serial available(unregister)"
            sys.exit(-1)
 

    xmldata= XmlParser().dictToXml(zfs_config)

    # if dumpxml provided then dump xml
    index = -1
    try :
        index = sys.argv.index("--dumpxml")
    except:
        print
    if index != -1 :
        try:
            fd = open("/tmp/dumpInfo.xml","w")
            fd.write(xmldata)
            print 'xml data available at /tmp/dumpInfo.xml'
            fd.close()
        except:
            print 'can`t open /tmp/dumpInfo.xml for writing'

    # web service to register user
    ret =  server._sa( '%s/SendMachineDetails' %ns ).SendMachineDetails( inputxmlfile=xmldata )
    retEcho = {'0'  : "Machine Restistation successful", 
               '1'  : "Machine Registeded Allready", 
               '2'  : "Key-user pair mismatch", 
               '3'  : "auhthentication fail", 
               '4'  : "Unsuffecient credentials", 
               '5'  : "Exeeding the installation limit6", 
               '7'  : "Database exception occured", 
               '8'  : "IO Exception", 
               '9'  : "Unknow error"  }
     
    # get default serial
    if ret == '0' :
        try:
            fd = open(ZFS_SERIAL,"w")
            fd.write(zfs_config['key'])
            fd.close()
        except:
            print "Unable to save credentials (product key)"
            print "Please put you product key %s to file %s manually for future use" % (zfs_config['key'],ZFS_SERIAL)
                   
    if retEcho.get(ret) == None:
        print "Got unknown response"
        return -1
    else:
        print "Got Response : " + retEcho[ret]

    return
#    sys.exit(0)
 



if __name__ == '__main__':

    main()
#    sys.exit(0)
