import struct
import logging

from twisted.internet.protocol import Protocol
from twisted.internet import defer, reactor


import topka.protobuf.pbRPC_pb2 as pbRPC_pb2

logger = logging.getLogger("pbrpc")

REQUEST_TIMEOUT = 5.0


class PbrpcProtocol(Protocol):
    ''' @summary: '''
    
    ICP_WAITING_LEN, ICP_WAITING_BODY = range(2)

    def __init__(self, factory, ctorMapper):
        self.factory = factory
        self.ctorMapper = ctorMapper
        self.reset()
        
    def reset(self):
        self.data = bytes([])
        self.state = self.ICP_WAITING_LEN
        self.bodyLen = 0
        self.pendingRequests = {}
        self.tagCounter = 1
        
    def connectionMade(self):
        self.reset()
    
    def dataReceived(self, data):
        ''' callback called when some bytes arrives from the socket
            @param data: incoming bytes
        '''
        self.data += data
        
        while len(self.data):
            if self.state == self.ICP_WAITING_LEN:
                if len(self.data) < 4:
                    return
                
                self.bodyLen = struct.unpack("!i", self.data[0:4])[0]
                self.state = self.ICP_WAITING_BODY
                self.data = self.data[4:]
                # print("message, len=%d" % self.bodyLen)
            
            if self.state == self.ICP_WAITING_BODY:
                if len(self.data) < self.bodyLen:
                    return
            
                packet = self.data[0:self.bodyLen]
                self.data = self.data[self.bodyLen:]
                
                baseRpc = pbRPC_pb2.RPCBase()
                baseRpc.ParseFromString(packet)

                if baseRpc.isResponse:
                    self.treat_response(baseRpc)
                else:
                    self.treat_request(baseRpc)
                
                self.state = self.ICP_WAITING_LEN
    
    def answer404(self, pbRpc):
        ''' answers a "404 not found" like message in the pcbRpc terminology
            @param pbRpc: the incoming request that will be used to forge an answer
            @return: 404 as error code 
        '''
        pbRpc.status = pbRPC_pb2.RPCBase.NOTFOUND
        pbRpc.isResponse = True
        pbRpc.payload = ''
        response = pbRpc.SerializeToString()
        self.transport.write( struct.pack("!i", len(response)) )                  
        self.transport.write( response )
    
    def buildQuery(self, msgType, payload, handler):
        self.tagCounter += 1
        return (msgType, self.tagCounter, handler, payload, True)

    def buildResponse(self, msgType, tag, payload):
        return (msgType, tag, None, payload, True)

    def sendMessages(self, messages):
        def sendPayload(msgType, tag, handler, payload, msgInPayload):
            msg = pbRPC_pb2.RPCBase()
            msg.msgType = msgType
            msg.tag = tag
            msg.status = pbRPC_pb2.RPCBase.SUCCESS
            msg.isResponse = (handler is None)
            if msgInPayload:
                msg.payload = payload.SerializeToString()
            else:
                msg.versionInfo.vmajor = payload.vmajor
                msg.versionInfo.vminor = payload.vminor
            response = msg.SerializeToString()
            self.transport.write( struct.pack("!i", len(response)) + response)
            
            if handler:
                # if we have a handler it's a request, and handler will handle the response 
                def timeoutCb():
                    watchdogAndDefer = self.pendingRequests.pop(tag, None)
                    if watchdogAndDefer:
                        (w, defer) =  watchdogAndDefer
                        logger.error("request tag={0} is in timeout".format(tag))
                        defer.callback((pbRPC_pb2.RPCBase.FAILED, None))

                deferredWatchdog = reactor.callLater(REQUEST_TIMEOUT, timeoutCb)
                self.pendingRequests[tag] = (deferredWatchdog, handler)
        
        for (msgType, tag, handler, payload, msgInPayload) in messages:
            sendPayload(msgType, tag, handler, payload, msgInPayload)
    
    
    def treat_request(self, pbRpc):
        payload = pbRpc.payload            
            
        cbInfos = self.ctorMapper.get(pbRpc.msgType, None)         
        if cbInfos is None:
            logger.error("PbRpcHandler(): unknown method with id={0}".format(pbRpc.msgType))
            return self.answer404(pbRpc)
        
        (methodName, ctor) = cbInfos
        toCall = getattr(self.factory, methodName, None)
        if not callable(toCall):
            logger.error("PbRpcHandler(): unknown method with id={0}(not callable)".format(pbRpc.msgType))
            return self.answer404(pbRpc)                        
                     
        if pbRpc.HasField("versionInfo"): 
            obj = pbRpc.versionInfo
        else:
            obj = ctor()
            obj.ParseFromString(payload)

        def sendMessagesCb(ret):
            if not isinstance(ret, list):
                # (msgType, tag, deferred, payload, msgInPayload)
                ret = [(pbRpc.msgType, pbRpc.tag, None, ret, True)]

            self.sendMessages(ret)
            
        def deferredError(failure):
            logger.error('call failed to {0}: {1}'.format(methodName, failure))
            msg = pbRPC_pb2.RPCBase()
            msg.msgType = pbRpc.msgType
            msg.tag = pbRpc.tag
            msg.status = pbRPC_pb2.RPCBase.FAILED
            msg.isResponse = True
            msg.payload = failure
            response = msg.SerializeToString()
            self.transport.write( struct.pack("!i", len(response)) + response)
        
        ret = toCall(pbRpc, obj)
        if not ret is None:
            if not isinstance(ret, defer.Deferred):
                ret = defer.succeed(ret)

            ret.addCallbacks(sendMessagesCb, deferredError)

    def treat_response(self, pbRpc):
        deferAndWatchdog = self.pendingRequests.pop(pbRpc.tag, None)
        if deferAndWatchdog:
            logger.debug('treat_reponse: tag={0} msgType={1} status={2} payloadLen={3}'.format(pbRpc.tag, pbRpc.msgType, pbRpc.status, len(pbRpc.payload)))
            
            (watchdog, d) = deferAndWatchdog
            if watchdog.active():
                logger.debug('killing watchdog for request tag={0}'.format(pbRpc.tag))
                watchdog.cancel()

            d.callback((pbRpc.status, pbRpc.payload))
        else:
            logger.error("treat_response(): receiving a response(tag={0} type={1}) but no request is registered here".format(pbRpc.tag, pbRpc.msgType))

