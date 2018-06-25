import string
import random
import socket
import struct
import logging
import pwd
import os
import time

tokenChars = string.ascii_letters + string.digits

def generateToken(tokenLen=50):
    return ''.join(random.sample(tokenChars, tokenLen))

def convertFormatString(v):
    ret = ""
    startPos = 0
    while True:
        #               v startIndex
        #    ...........${var}
        # startPos^          ^ endIndex
        startIndex = v.find("${", startPos)
        if startIndex < 0:
            ret += v[startPos:]
            return ret
        
        endIndex = v.find("}", startIndex+2)
        if endIndex < 0: 
            ret += v[startPos:]
            return ret
        
        ret += v[startPos : startIndex]
        ret += "%(" + v[startIndex+2 : endIndex] + ")s"
        startPos = endIndex + 1

def expandVars(strIn, context):
    if strIn.find("${") < 0:
        return strIn
    
    fmt = convertFormatString(strIn)
    return fmt % context

def toFileTime(time_t):
    return int((time_t + 11644473600) * 10000000)

def fromFileTime(t):
    return time.gmtime( (t / 10000000) - 11644473600) 

class PeerCredentials(object):
    ''' identity of the socket peer '''
    def __init__(self, uid, gid, pid = None):
        self.uid = uid
        self.gid = gid
        self.pid = pid
        
def getPeerCredential(sock):
    SO_PEERCRED = 17 # Pulled from /usr/include/asm-generic/socket.h
    creds = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize('3i'))
    pid, uid, gid = struct.unpack('3i', creds)
    return PeerCredentials(uid, gid, pid)

def hexadump(s):
    ret = ''
    hexa = s.encode('hex')
    while len(hexa):
        ret += hexa[0:2] + " "
        hexa = hexa[2:]
    return ret

def buildMethodDescriptor(module, methods):
    logger = logging.getLogger("utils")
    ret = {}
    for messageIdName in methods:
        messageId = getattr(module, messageIdName, None)
        if messageId is None:
            logger.error("unable to retrieve %s" % messageIdName)
            continue
        
        reqCtor = getattr(module, messageIdName + "Request", None)
        if reqCtor is None:
            logger.error("unable to retrieve %sRequest" % messageIdName)
            continue
        ret[messageId] = (messageIdName, reqCtor)
    return ret

def resolveUser(user = None):
    if user is None:
        infos = pwd.getpwuid(os.getuid())
    else:
        infos = pwd.getpwnam(user)
    
    return {
        'login': infos.pw_name,
        'uid': infos.pw_uid,
        'gid': infos.pw_gid,
        'home': infos.pw_dir,
        'shell': infos.pw_shell,
    }
