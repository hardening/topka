import sys
import getopt
import os
import time

from twisted.internet import reactor, ssl, defer
from twisted.internet.protocol import ClientCreator
from twisted.internet.defer import inlineCallbacks

from thrift.transport import TTwisted
from thrift.protocol import TBinaryProtocol

from topka.thriftstubs.otsapi import otsapi
from topka import wtsapi, utils
import traceback
from topka.thriftstubs.otsapi.ttypes import TVersion


def readAuthToken(sid):
    with open('/tmp/ogon.session.{0}'.format(sid), "rt") as f:
        return f.readline().strip()

  
def getAuthToken(stub, authUser, authDomain, authPassword):
    if not authUser:
        try:
            if 'OGON_SID' in os.environ:
                ogonSid = int(os.environ['OGON_SID'])
            return defer.succeed((False, readAuthToken(ogonSid),))
        except:
            print("failed to use OGON_SID")
        
        while not authUser:
            print('enter username:', end='', flush=True)
            authUser = sys.stdin.readline()[:-1]
    
        tokens = authUser.split('@')
        authUser = tokens[0]
        if len(tokens) > 1:
            authDomain = tokens[1]

    while not authDomain:
        print('enter domain:', end='', flush=True)
        authDomain = sys.stdin.readline()[:-1]

    while not authPassword:
        print('enter password:', end='', flush=True)
        authPassword = sys.stdin.readline()[:-1]
    
    def reqCallback(r):
        if r.success:
            return (True, r.authToken,)
        return defer.fail(Exception('invalid login / password'))
         
    return stub.logonConnection(authUser, authPassword, authDomain).addCallback(reqCallback)
    
sessionStateNames = {
    wtsapi.WTSActive: "active", 
    wtsapi.WTSConnected: "connected" , 
    wtsapi.WTSConnectQuery: "connectQuery", 
    wtsapi.WTSShadow: "shadowing", 
    wtsapi.WTSDisconnected: "disconnected", 
    wtsapi.WTSIdle: "idle", 
    wtsapi.WTSListen: "listen", 
    wtsapi.WTSReset: "reset", 
    wtsapi.WTSDown: "down", 
    wtsapi.WTSInit: "init"
}

def usage(args):
    print('usage: {0} [-u|--user=<user>] [-d|--domain=<domain>] [-t|--target=<serverAddr:port>] [-s|sessionId=<sessionId>]' +
          ' [--targetId=<sessionId>] [--keys=<key sequence>] [--no-mouse] [--no-keyboard] [--no-input] ' + 
          '--title=<title> --message=<message> --nowait <command>'.format(args[0]))
    print(' - commands:')
    print('    getVersion: shows the version of topka')
    print('    listSessions: list currently running sessions')
    print('    logoffSession: kills the given session')
    print('    sessionDetails: retrieve all details about a given session')
    print('    startShadowing: starts the shadowing of a session')
    print('    stopShadowing: stops the shadowing of a session')
    print('    sendMessage: prints a message in the user session')

modifiersNames = {
    "Alt":      wtsapi.REMOTECONTROL_KBDALT_HOTKEY,
    "Ctrl":     wtsapi.REMOTECONTROL_KBDCTRL_HOTKEY,
    "Shift":    wtsapi.REMOTECONTROL_KBDSHIFT_HOTKEY
}

def main(args=None):
    if args is None:
        args = sys.argv
        
    if len(args) == 1:
        usage(args)
        return 1
    
    try:
        opts, extraArgs = getopt.getopt(args[1:], 's:t:u:d:', 
            ['sessionId=', 'target=', 'user=', 'domain=', 'targetId=', 'keys=', 'no-mouse', 'no-keyboard', 'no-input',
             'title=', 'message=']
        )
    except getopt.GetoptError as err:
        sys.stderr.write('error parsing args: {0}'.format(err));
        return 1

    sessionId = int(os.environ.get('OGON_SID', '0'))
    targetServer = ('127.0.0.1', 9091)
    targetId = None
    authUser = None
    authDomain = ''
    authPassword = None
    
    keySeq = wtsapi.VK_F10
    keyModifiers = wtsapi.REMOTECONTROL_KBDALT_HOTKEY
    shadowFlags = 0
    
    userTitle = None
    userMessage = None
    userWait = True
    
    for option, value in opts:
        if option in ('-s', '--sessionId',):
            sessionId = int(value)
        elif option in ('-t', '--target',):
            tokens = value.split(':', 2)
            targetServer = (tokens[0], int(tokens[1]))
        elif option in ('--targetId',):
            targetId = int(value)
        elif option in ('-u', '--user',):
            tokens = value.split('@', 2)
            authUser = tokens[0]
            if len(tokens) > 1:
                authDomain = tokens[1]
        elif option in ('-d', '--domain',):
            authDomain = value
        elif option in ('--keys',):
            tokens = value.split('+')
            keyModifiers = 0
            keySeq = 0
            for k in tokens:
                if k in modifiersNames:
                    keyModifiers |= modifiersNames[k]
                elif k in wtsapi.VK:
                    keySeq = wtsapi.VK[k]
            
            if keySeq == 0:
                print('missing key in key sequence')
                sys.exit(1)
        elif option in ('--no-mouse',):
            shadowFlags |= wtsapi.REMOTECONTROL_FLAG_DISABLE_MOUSE
        elif option in ('--no-keyboard',):
            shadowFlags |= wtsapi.REMOTECONTROL_FLAG_DISABLE_KEYBOARD
        elif option in ('--no-input',):
            shadowFlags |= wtsapi.REMOTECONTROL_FLAG_DISABLE_INPUT
        elif option in ('--title',):
            userTitle = value
        elif option in ('--message',):
            userMessage = value
        elif option in ('--nowait',):
            userWait = False
        else:
            print('unknown option {0}'.format(option))
            sys.exit(1)


    if not len(extraArgs):
        usage(args)
        sys.exit(1)
    
    authPassword = authUser
    command = extraArgs[0]

    @inlineCallbacks
    def executeCommand(conn):
        try:
            # ping the topka to see if it is running
            client = conn.client
            ret = yield client.ping(0xff) 
            if ret != 0xff:
                raise Exception('topka sessionManager not running')
            
            doKillToken = False
            authToken = ''
            if command in ('listSessions', 'logoffSession', 'sessionDetails', 'startShadowing', 'stopShadowing', 'sendMessage',):
                # commands that need the authentication token
                (doKillToken, authToken) = yield getAuthToken(client, authUser, authDomain, authPassword)

            if command == 'getVersion':
                v = TVersion(1, 1)
                ret = yield client.getVersionInfo(v)
                print("remote version is {0}.{1}".format(ret.VersionMajor, ret.VersionMinor))
              
            elif command == 'listSessions':
                print("listing sessions:")
                ret = yield client.enumerateSessions(authToken, 1)

                if not ret.returnValue:
                    print('error listing sessions')
                else:
                    print('id\tstate\thostname')
                    for s in ret.sessionInfoList:
                        state = sessionStateNames.get(s.connectState, "<unknown {0}>".format(s.connectState))
                        print("{0}\t{1}\t{2}".format(s.sessionId, state, s.winStationName)) 

                    print('{0} sessions'.format(len(ret.sessionInfoList)))
            
            elif command == 'logoffSession':
                # bool logoffSession(1:TSTRING authToken, 2:TDWORD sessionId, 3:TBOOL wait);
                ret = yield client.logoffSession(authToken, sessionId, True)
                print("loggingOff session {0}: {1}".format(sessionId, ret and 'success' or 'failure'))
                
            elif command == 'sessionDetails':
                ret = yield client.querySessionInformation(authToken, sessionId, wtsapi.WTSSessionInfo)
                if not ret.returnValue:
                    print("an error occured when querying session informations")
                else:
                    wtsinfo = ret.infoValue.WTSINFO
                    print ("session details for {0}:".format(wtsinfo.SessionId))
                    if wtsinfo.UserName:
                        fullUser = wtsinfo.UserName + "@" + wtsinfo.Domain
                    else:
                        fullUser = "<anonymous>"
                    
                    currentTime = wtsinfo.CurrentTime
                    print(" * state: {0}".format( sessionStateNames.get(wtsinfo.State, "<unknown {0}>".format(wtsinfo.State))) )
                    print(" * user/domain: {0}".format(fullUser))
                    print(" * stationName: {0}".format(wtsinfo.WinStationName))
                    connectTime = utils.fromFileTime(wtsinfo.ConnectTime)
                    print(" * connect time: {0}".format(time.strftime("%H:%M:%S-%d %b %Y", connectTime)))
                    print(" * traffic stats: in={0}({1}) out={2}({3})"
                          .format(wtsinfo.IncomingBytes, wtsinfo.IncomingFrames, wtsinfo.OutgoingBytes, wtsinfo.OutgoingFrames))
            
            elif command == 'startShadowing':
                ret = yield client.startRemoteControlSession(authToken, sessionId, targetId, keySeq, keyModifiers, shadowFlags)
                if not ret:
                    print ('error enabling shadowing') 

            elif command == 'stopShadowing':
                ret = yield client.stopRemoteControlSession(authToken, sessionId, targetId)
                if not ret:
                    print ('error stopping shadowing')
            elif command == 'sendMessage':
                ret = yield client.sendMessage(authToken, sessionId, userTitle, userMessage, wtsapi.MB_OK, 10, userWait);
                
            if doKillToken:
                ret = yield client.logoffConnection(authToken)
                if not ret:
                    print("unable to kill authenticated connection")
        except:
            traceback.print_exc()
                
        reactor.stop()

    def connectError(e):
        print('error={0}'.format(e))
        reactor.stop()
        
    client = ClientCreator(reactor, TTwisted.ThriftClientProtocol, otsapi.Client, 
                           TBinaryProtocol.TBinaryProtocolFactory(),
                           ).connectSSL(targetServer[0], targetServer[1], ssl.ClientContextFactory())
    client.addCallbacks(executeCommand, connectError)
    reactor.run()
    return 0

if __name__ == '__main__':
    sys.exit( main(sys.argv) )
    