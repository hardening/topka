#
# Autogenerated by Thrift Compiler (0.11.0)
#
# DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
#
#  options string: py:twisted
#

from thrift.Thrift import TType, TMessageType, TFrozenDict, TException, TApplicationException
from thrift.protocol.TProtocol import TProtocolException
from thrift.TRecursive import fix_spec

import sys

from thrift.transport import TTransport
all_structs = []


class TVersion(object):
    """
    Attributes:
     - VersionMajor
     - VersionMinor
    """


    def __init__(self, VersionMajor=None, VersionMinor=None,):
        self.VersionMajor = VersionMajor
        self.VersionMinor = VersionMinor

    def read(self, iprot):
        if iprot._fast_decode is not None and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None:
            iprot._fast_decode(self, iprot, [self.__class__, self.thrift_spec])
            return
        iprot.readStructBegin()
        while True:
            (fname, ftype, fid) = iprot.readFieldBegin()
            if ftype == TType.STOP:
                break
            if fid == 1:
                if ftype == TType.I32:
                    self.VersionMajor = iprot.readI32()
                else:
                    iprot.skip(ftype)
            elif fid == 2:
                if ftype == TType.I32:
                    self.VersionMinor = iprot.readI32()
                else:
                    iprot.skip(ftype)
            else:
                iprot.skip(ftype)
            iprot.readFieldEnd()
        iprot.readStructEnd()

    def write(self, oprot):
        if oprot._fast_encode is not None and self.thrift_spec is not None:
            oprot.trans.write(oprot._fast_encode(self, [self.__class__, self.thrift_spec]))
            return
        oprot.writeStructBegin('TVersion')
        if self.VersionMajor is not None:
            oprot.writeFieldBegin('VersionMajor', TType.I32, 1)
            oprot.writeI32(self.VersionMajor)
            oprot.writeFieldEnd()
        if self.VersionMinor is not None:
            oprot.writeFieldBegin('VersionMinor', TType.I32, 2)
            oprot.writeI32(self.VersionMinor)
            oprot.writeFieldEnd()
        oprot.writeFieldStop()
        oprot.writeStructEnd()

    def validate(self):
        return

    def __repr__(self):
        L = ['%s=%r' % (key, value)
             for key, value in self.__dict__.items()]
        return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not (self == other)


class TSessionInfo(object):
    """
    Attributes:
     - sessionId
     - winStationName
     - connectState
    """


    def __init__(self, sessionId=None, winStationName=None, connectState=None,):
        self.sessionId = sessionId
        self.winStationName = winStationName
        self.connectState = connectState

    def read(self, iprot):
        if iprot._fast_decode is not None and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None:
            iprot._fast_decode(self, iprot, [self.__class__, self.thrift_spec])
            return
        iprot.readStructBegin()
        while True:
            (fname, ftype, fid) = iprot.readFieldBegin()
            if ftype == TType.STOP:
                break
            if fid == 1:
                if ftype == TType.I32:
                    self.sessionId = iprot.readI32()
                else:
                    iprot.skip(ftype)
            elif fid == 2:
                if ftype == TType.STRING:
                    self.winStationName = iprot.readString().decode('utf-8') if sys.version_info[0] == 2 else iprot.readString()
                else:
                    iprot.skip(ftype)
            elif fid == 3:
                if ftype == TType.I32:
                    self.connectState = iprot.readI32()
                else:
                    iprot.skip(ftype)
            else:
                iprot.skip(ftype)
            iprot.readFieldEnd()
        iprot.readStructEnd()

    def write(self, oprot):
        if oprot._fast_encode is not None and self.thrift_spec is not None:
            oprot.trans.write(oprot._fast_encode(self, [self.__class__, self.thrift_spec]))
            return
        oprot.writeStructBegin('TSessionInfo')
        if self.sessionId is not None:
            oprot.writeFieldBegin('sessionId', TType.I32, 1)
            oprot.writeI32(self.sessionId)
            oprot.writeFieldEnd()
        if self.winStationName is not None:
            oprot.writeFieldBegin('winStationName', TType.STRING, 2)
            oprot.writeString(self.winStationName.encode('utf-8') if sys.version_info[0] == 2 else self.winStationName)
            oprot.writeFieldEnd()
        if self.connectState is not None:
            oprot.writeFieldBegin('connectState', TType.I32, 3)
            oprot.writeI32(self.connectState)
            oprot.writeFieldEnd()
        oprot.writeFieldStop()
        oprot.writeStructEnd()

    def validate(self):
        return

    def __repr__(self):
        L = ['%s=%r' % (key, value)
             for key, value in self.__dict__.items()]
        return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not (self == other)


class TReturnEnumerateSession(object):
    """
    Attributes:
     - returnValue
     - sessionInfoList
    """


    def __init__(self, returnValue=None, sessionInfoList=None,):
        self.returnValue = returnValue
        self.sessionInfoList = sessionInfoList

    def read(self, iprot):
        if iprot._fast_decode is not None and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None:
            iprot._fast_decode(self, iprot, [self.__class__, self.thrift_spec])
            return
        iprot.readStructBegin()
        while True:
            (fname, ftype, fid) = iprot.readFieldBegin()
            if ftype == TType.STOP:
                break
            if fid == 1:
                if ftype == TType.BOOL:
                    self.returnValue = iprot.readBool()
                else:
                    iprot.skip(ftype)
            elif fid == 2:
                if ftype == TType.LIST:
                    self.sessionInfoList = []
                    (_etype3, _size0) = iprot.readListBegin()
                    for _i4 in range(_size0):
                        _elem5 = TSessionInfo()
                        _elem5.read(iprot)
                        self.sessionInfoList.append(_elem5)
                    iprot.readListEnd()
                else:
                    iprot.skip(ftype)
            else:
                iprot.skip(ftype)
            iprot.readFieldEnd()
        iprot.readStructEnd()

    def write(self, oprot):
        if oprot._fast_encode is not None and self.thrift_spec is not None:
            oprot.trans.write(oprot._fast_encode(self, [self.__class__, self.thrift_spec]))
            return
        oprot.writeStructBegin('TReturnEnumerateSession')
        if self.returnValue is not None:
            oprot.writeFieldBegin('returnValue', TType.BOOL, 1)
            oprot.writeBool(self.returnValue)
            oprot.writeFieldEnd()
        if self.sessionInfoList is not None:
            oprot.writeFieldBegin('sessionInfoList', TType.LIST, 2)
            oprot.writeListBegin(TType.STRUCT, len(self.sessionInfoList))
            for iter6 in self.sessionInfoList:
                iter6.write(oprot)
            oprot.writeListEnd()
            oprot.writeFieldEnd()
        oprot.writeFieldStop()
        oprot.writeStructEnd()

    def validate(self):
        return

    def __repr__(self):
        L = ['%s=%r' % (key, value)
             for key, value in self.__dict__.items()]
        return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not (self == other)


class TReturnVirtualChannelOpen(object):
    """
    Attributes:
     - pipeName
     - instance
    """


    def __init__(self, pipeName=None, instance=None,):
        self.pipeName = pipeName
        self.instance = instance

    def read(self, iprot):
        if iprot._fast_decode is not None and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None:
            iprot._fast_decode(self, iprot, [self.__class__, self.thrift_spec])
            return
        iprot.readStructBegin()
        while True:
            (fname, ftype, fid) = iprot.readFieldBegin()
            if ftype == TType.STOP:
                break
            if fid == 1:
                if ftype == TType.STRING:
                    self.pipeName = iprot.readString().decode('utf-8') if sys.version_info[0] == 2 else iprot.readString()
                else:
                    iprot.skip(ftype)
            elif fid == 2:
                if ftype == TType.I32:
                    self.instance = iprot.readI32()
                else:
                    iprot.skip(ftype)
            else:
                iprot.skip(ftype)
            iprot.readFieldEnd()
        iprot.readStructEnd()

    def write(self, oprot):
        if oprot._fast_encode is not None and self.thrift_spec is not None:
            oprot.trans.write(oprot._fast_encode(self, [self.__class__, self.thrift_spec]))
            return
        oprot.writeStructBegin('TReturnVirtualChannelOpen')
        if self.pipeName is not None:
            oprot.writeFieldBegin('pipeName', TType.STRING, 1)
            oprot.writeString(self.pipeName.encode('utf-8') if sys.version_info[0] == 2 else self.pipeName)
            oprot.writeFieldEnd()
        if self.instance is not None:
            oprot.writeFieldBegin('instance', TType.I32, 2)
            oprot.writeI32(self.instance)
            oprot.writeFieldEnd()
        oprot.writeFieldStop()
        oprot.writeStructEnd()

    def validate(self):
        return

    def __repr__(self):
        L = ['%s=%r' % (key, value)
             for key, value in self.__dict__.items()]
        return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not (self == other)


class TClientDisplay(object):
    """
    Attributes:
     - displayWidth
     - displayHeight
     - colorDepth
    """


    def __init__(self, displayWidth=None, displayHeight=None, colorDepth=None,):
        self.displayWidth = displayWidth
        self.displayHeight = displayHeight
        self.colorDepth = colorDepth

    def read(self, iprot):
        if iprot._fast_decode is not None and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None:
            iprot._fast_decode(self, iprot, [self.__class__, self.thrift_spec])
            return
        iprot.readStructBegin()
        while True:
            (fname, ftype, fid) = iprot.readFieldBegin()
            if ftype == TType.STOP:
                break
            if fid == 1:
                if ftype == TType.I32:
                    self.displayWidth = iprot.readI32()
                else:
                    iprot.skip(ftype)
            elif fid == 2:
                if ftype == TType.I32:
                    self.displayHeight = iprot.readI32()
                else:
                    iprot.skip(ftype)
            elif fid == 3:
                if ftype == TType.I32:
                    self.colorDepth = iprot.readI32()
                else:
                    iprot.skip(ftype)
            else:
                iprot.skip(ftype)
            iprot.readFieldEnd()
        iprot.readStructEnd()

    def write(self, oprot):
        if oprot._fast_encode is not None and self.thrift_spec is not None:
            oprot.trans.write(oprot._fast_encode(self, [self.__class__, self.thrift_spec]))
            return
        oprot.writeStructBegin('TClientDisplay')
        if self.displayWidth is not None:
            oprot.writeFieldBegin('displayWidth', TType.I32, 1)
            oprot.writeI32(self.displayWidth)
            oprot.writeFieldEnd()
        if self.displayHeight is not None:
            oprot.writeFieldBegin('displayHeight', TType.I32, 2)
            oprot.writeI32(self.displayHeight)
            oprot.writeFieldEnd()
        if self.colorDepth is not None:
            oprot.writeFieldBegin('colorDepth', TType.I32, 3)
            oprot.writeI32(self.colorDepth)
            oprot.writeFieldEnd()
        oprot.writeFieldStop()
        oprot.writeStructEnd()

    def validate(self):
        return

    def __repr__(self):
        L = ['%s=%r' % (key, value)
             for key, value in self.__dict__.items()]
        return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not (self == other)


class TWTSINFO(object):
    """
    Attributes:
     - State
     - SessionId
     - IncomingBytes
     - OutgoingBytes
     - IncomingFrames
     - OutgoingFrames
     - IncomingCompressedBytes
     - OutgoingCompressedBytes
     - WinStationName
     - Domain
     - UserName
     - ConnectTime
     - DisconnectTime
     - LastInputTime
     - LogonTime
     - CurrentTime
    """


    def __init__(self, State=None, SessionId=None, IncomingBytes=None, OutgoingBytes=None, IncomingFrames=None, OutgoingFrames=None, IncomingCompressedBytes=None, OutgoingCompressedBytes=None, WinStationName=None, Domain=None, UserName=None, ConnectTime=None, DisconnectTime=None, LastInputTime=None, LogonTime=None, CurrentTime=None,):
        self.State = State
        self.SessionId = SessionId
        self.IncomingBytes = IncomingBytes
        self.OutgoingBytes = OutgoingBytes
        self.IncomingFrames = IncomingFrames
        self.OutgoingFrames = OutgoingFrames
        self.IncomingCompressedBytes = IncomingCompressedBytes
        self.OutgoingCompressedBytes = OutgoingCompressedBytes
        self.WinStationName = WinStationName
        self.Domain = Domain
        self.UserName = UserName
        self.ConnectTime = ConnectTime
        self.DisconnectTime = DisconnectTime
        self.LastInputTime = LastInputTime
        self.LogonTime = LogonTime
        self.CurrentTime = CurrentTime

    def read(self, iprot):
        if iprot._fast_decode is not None and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None:
            iprot._fast_decode(self, iprot, [self.__class__, self.thrift_spec])
            return
        iprot.readStructBegin()
        while True:
            (fname, ftype, fid) = iprot.readFieldBegin()
            if ftype == TType.STOP:
                break
            if fid == 1:
                if ftype == TType.I32:
                    self.State = iprot.readI32()
                else:
                    iprot.skip(ftype)
            elif fid == 2:
                if ftype == TType.I32:
                    self.SessionId = iprot.readI32()
                else:
                    iprot.skip(ftype)
            elif fid == 3:
                if ftype == TType.I32:
                    self.IncomingBytes = iprot.readI32()
                else:
                    iprot.skip(ftype)
            elif fid == 4:
                if ftype == TType.I32:
                    self.OutgoingBytes = iprot.readI32()
                else:
                    iprot.skip(ftype)
            elif fid == 5:
                if ftype == TType.I32:
                    self.IncomingFrames = iprot.readI32()
                else:
                    iprot.skip(ftype)
            elif fid == 6:
                if ftype == TType.I32:
                    self.OutgoingFrames = iprot.readI32()
                else:
                    iprot.skip(ftype)
            elif fid == 7:
                if ftype == TType.I32:
                    self.IncomingCompressedBytes = iprot.readI32()
                else:
                    iprot.skip(ftype)
            elif fid == 8:
                if ftype == TType.I32:
                    self.OutgoingCompressedBytes = iprot.readI32()
                else:
                    iprot.skip(ftype)
            elif fid == 9:
                if ftype == TType.STRING:
                    self.WinStationName = iprot.readString().decode('utf-8') if sys.version_info[0] == 2 else iprot.readString()
                else:
                    iprot.skip(ftype)
            elif fid == 10:
                if ftype == TType.STRING:
                    self.Domain = iprot.readString().decode('utf-8') if sys.version_info[0] == 2 else iprot.readString()
                else:
                    iprot.skip(ftype)
            elif fid == 11:
                if ftype == TType.STRING:
                    self.UserName = iprot.readString().decode('utf-8') if sys.version_info[0] == 2 else iprot.readString()
                else:
                    iprot.skip(ftype)
            elif fid == 12:
                if ftype == TType.I64:
                    self.ConnectTime = iprot.readI64()
                else:
                    iprot.skip(ftype)
            elif fid == 13:
                if ftype == TType.I64:
                    self.DisconnectTime = iprot.readI64()
                else:
                    iprot.skip(ftype)
            elif fid == 14:
                if ftype == TType.I64:
                    self.LastInputTime = iprot.readI64()
                else:
                    iprot.skip(ftype)
            elif fid == 15:
                if ftype == TType.I64:
                    self.LogonTime = iprot.readI64()
                else:
                    iprot.skip(ftype)
            elif fid == 16:
                if ftype == TType.I64:
                    self.CurrentTime = iprot.readI64()
                else:
                    iprot.skip(ftype)
            else:
                iprot.skip(ftype)
            iprot.readFieldEnd()
        iprot.readStructEnd()

    def write(self, oprot):
        if oprot._fast_encode is not None and self.thrift_spec is not None:
            oprot.trans.write(oprot._fast_encode(self, [self.__class__, self.thrift_spec]))
            return
        oprot.writeStructBegin('TWTSINFO')
        if self.State is not None:
            oprot.writeFieldBegin('State', TType.I32, 1)
            oprot.writeI32(self.State)
            oprot.writeFieldEnd()
        if self.SessionId is not None:
            oprot.writeFieldBegin('SessionId', TType.I32, 2)
            oprot.writeI32(self.SessionId)
            oprot.writeFieldEnd()
        if self.IncomingBytes is not None:
            oprot.writeFieldBegin('IncomingBytes', TType.I32, 3)
            oprot.writeI32(self.IncomingBytes)
            oprot.writeFieldEnd()
        if self.OutgoingBytes is not None:
            oprot.writeFieldBegin('OutgoingBytes', TType.I32, 4)
            oprot.writeI32(self.OutgoingBytes)
            oprot.writeFieldEnd()
        if self.IncomingFrames is not None:
            oprot.writeFieldBegin('IncomingFrames', TType.I32, 5)
            oprot.writeI32(self.IncomingFrames)
            oprot.writeFieldEnd()
        if self.OutgoingFrames is not None:
            oprot.writeFieldBegin('OutgoingFrames', TType.I32, 6)
            oprot.writeI32(self.OutgoingFrames)
            oprot.writeFieldEnd()
        if self.IncomingCompressedBytes is not None:
            oprot.writeFieldBegin('IncomingCompressedBytes', TType.I32, 7)
            oprot.writeI32(self.IncomingCompressedBytes)
            oprot.writeFieldEnd()
        if self.OutgoingCompressedBytes is not None:
            oprot.writeFieldBegin('OutgoingCompressedBytes', TType.I32, 8)
            oprot.writeI32(self.OutgoingCompressedBytes)
            oprot.writeFieldEnd()
        if self.WinStationName is not None:
            oprot.writeFieldBegin('WinStationName', TType.STRING, 9)
            oprot.writeString(self.WinStationName.encode('utf-8') if sys.version_info[0] == 2 else self.WinStationName)
            oprot.writeFieldEnd()
        if self.Domain is not None:
            oprot.writeFieldBegin('Domain', TType.STRING, 10)
            oprot.writeString(self.Domain.encode('utf-8') if sys.version_info[0] == 2 else self.Domain)
            oprot.writeFieldEnd()
        if self.UserName is not None:
            oprot.writeFieldBegin('UserName', TType.STRING, 11)
            oprot.writeString(self.UserName.encode('utf-8') if sys.version_info[0] == 2 else self.UserName)
            oprot.writeFieldEnd()
        if self.ConnectTime is not None:
            oprot.writeFieldBegin('ConnectTime', TType.I64, 12)
            oprot.writeI64(self.ConnectTime)
            oprot.writeFieldEnd()
        if self.DisconnectTime is not None:
            oprot.writeFieldBegin('DisconnectTime', TType.I64, 13)
            oprot.writeI64(self.DisconnectTime)
            oprot.writeFieldEnd()
        if self.LastInputTime is not None:
            oprot.writeFieldBegin('LastInputTime', TType.I64, 14)
            oprot.writeI64(self.LastInputTime)
            oprot.writeFieldEnd()
        if self.LogonTime is not None:
            oprot.writeFieldBegin('LogonTime', TType.I64, 15)
            oprot.writeI64(self.LogonTime)
            oprot.writeFieldEnd()
        if self.CurrentTime is not None:
            oprot.writeFieldBegin('CurrentTime', TType.I64, 16)
            oprot.writeI64(self.CurrentTime)
            oprot.writeFieldEnd()
        oprot.writeFieldStop()
        oprot.writeStructEnd()

    def validate(self):
        return

    def __repr__(self):
        L = ['%s=%r' % (key, value)
             for key, value in self.__dict__.items()]
        return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not (self == other)


class TSessionInfoValue(object):
    """
    Attributes:
     - boolValue
     - int16Value
     - int32Value
     - stringValue
     - displayValue
     - WTSINFO
     - int64Value
    """


    def __init__(self, boolValue=None, int16Value=None, int32Value=None, stringValue=None, displayValue=None, WTSINFO=None, int64Value=None,):
        self.boolValue = boolValue
        self.int16Value = int16Value
        self.int32Value = int32Value
        self.stringValue = stringValue
        self.displayValue = displayValue
        self.WTSINFO = WTSINFO
        self.int64Value = int64Value

    def read(self, iprot):
        if iprot._fast_decode is not None and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None:
            iprot._fast_decode(self, iprot, [self.__class__, self.thrift_spec])
            return
        iprot.readStructBegin()
        while True:
            (fname, ftype, fid) = iprot.readFieldBegin()
            if ftype == TType.STOP:
                break
            if fid == 1:
                if ftype == TType.BOOL:
                    self.boolValue = iprot.readBool()
                else:
                    iprot.skip(ftype)
            elif fid == 2:
                if ftype == TType.I16:
                    self.int16Value = iprot.readI16()
                else:
                    iprot.skip(ftype)
            elif fid == 3:
                if ftype == TType.I32:
                    self.int32Value = iprot.readI32()
                else:
                    iprot.skip(ftype)
            elif fid == 4:
                if ftype == TType.STRING:
                    self.stringValue = iprot.readString().decode('utf-8') if sys.version_info[0] == 2 else iprot.readString()
                else:
                    iprot.skip(ftype)
            elif fid == 5:
                if ftype == TType.STRUCT:
                    self.displayValue = TClientDisplay()
                    self.displayValue.read(iprot)
                else:
                    iprot.skip(ftype)
            elif fid == 6:
                if ftype == TType.STRUCT:
                    self.WTSINFO = TWTSINFO()
                    self.WTSINFO.read(iprot)
                else:
                    iprot.skip(ftype)
            elif fid == 7:
                if ftype == TType.I64:
                    self.int64Value = iprot.readI64()
                else:
                    iprot.skip(ftype)
            else:
                iprot.skip(ftype)
            iprot.readFieldEnd()
        iprot.readStructEnd()

    def write(self, oprot):
        if oprot._fast_encode is not None and self.thrift_spec is not None:
            oprot.trans.write(oprot._fast_encode(self, [self.__class__, self.thrift_spec]))
            return
        oprot.writeStructBegin('TSessionInfoValue')
        if self.boolValue is not None:
            oprot.writeFieldBegin('boolValue', TType.BOOL, 1)
            oprot.writeBool(self.boolValue)
            oprot.writeFieldEnd()
        if self.int16Value is not None:
            oprot.writeFieldBegin('int16Value', TType.I16, 2)
            oprot.writeI16(self.int16Value)
            oprot.writeFieldEnd()
        if self.int32Value is not None:
            oprot.writeFieldBegin('int32Value', TType.I32, 3)
            oprot.writeI32(self.int32Value)
            oprot.writeFieldEnd()
        if self.stringValue is not None:
            oprot.writeFieldBegin('stringValue', TType.STRING, 4)
            oprot.writeString(self.stringValue.encode('utf-8') if sys.version_info[0] == 2 else self.stringValue)
            oprot.writeFieldEnd()
        if self.displayValue is not None:
            oprot.writeFieldBegin('displayValue', TType.STRUCT, 5)
            self.displayValue.write(oprot)
            oprot.writeFieldEnd()
        if self.WTSINFO is not None:
            oprot.writeFieldBegin('WTSINFO', TType.STRUCT, 6)
            self.WTSINFO.write(oprot)
            oprot.writeFieldEnd()
        if self.int64Value is not None:
            oprot.writeFieldBegin('int64Value', TType.I64, 7)
            oprot.writeI64(self.int64Value)
            oprot.writeFieldEnd()
        oprot.writeFieldStop()
        oprot.writeStructEnd()

    def validate(self):
        return

    def __repr__(self):
        L = ['%s=%r' % (key, value)
             for key, value in self.__dict__.items()]
        return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not (self == other)


class TReturnQuerySessionInformation(object):
    """
    Attributes:
     - returnValue
     - infoValue
    """


    def __init__(self, returnValue=None, infoValue=None,):
        self.returnValue = returnValue
        self.infoValue = infoValue

    def read(self, iprot):
        if iprot._fast_decode is not None and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None:
            iprot._fast_decode(self, iprot, [self.__class__, self.thrift_spec])
            return
        iprot.readStructBegin()
        while True:
            (fname, ftype, fid) = iprot.readFieldBegin()
            if ftype == TType.STOP:
                break
            if fid == 1:
                if ftype == TType.BOOL:
                    self.returnValue = iprot.readBool()
                else:
                    iprot.skip(ftype)
            elif fid == 2:
                if ftype == TType.STRUCT:
                    self.infoValue = TSessionInfoValue()
                    self.infoValue.read(iprot)
                else:
                    iprot.skip(ftype)
            else:
                iprot.skip(ftype)
            iprot.readFieldEnd()
        iprot.readStructEnd()

    def write(self, oprot):
        if oprot._fast_encode is not None and self.thrift_spec is not None:
            oprot.trans.write(oprot._fast_encode(self, [self.__class__, self.thrift_spec]))
            return
        oprot.writeStructBegin('TReturnQuerySessionInformation')
        if self.returnValue is not None:
            oprot.writeFieldBegin('returnValue', TType.BOOL, 1)
            oprot.writeBool(self.returnValue)
            oprot.writeFieldEnd()
        if self.infoValue is not None:
            oprot.writeFieldBegin('infoValue', TType.STRUCT, 2)
            self.infoValue.write(oprot)
            oprot.writeFieldEnd()
        oprot.writeFieldStop()
        oprot.writeStructEnd()

    def validate(self):
        return

    def __repr__(self):
        L = ['%s=%r' % (key, value)
             for key, value in self.__dict__.items()]
        return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not (self == other)


class TReturnLogonConnection(object):
    """
    Attributes:
     - success
     - authToken
    """


    def __init__(self, success=None, authToken=None,):
        self.success = success
        self.authToken = authToken

    def read(self, iprot):
        if iprot._fast_decode is not None and isinstance(iprot.trans, TTransport.CReadableTransport) and self.thrift_spec is not None:
            iprot._fast_decode(self, iprot, [self.__class__, self.thrift_spec])
            return
        iprot.readStructBegin()
        while True:
            (fname, ftype, fid) = iprot.readFieldBegin()
            if ftype == TType.STOP:
                break
            if fid == 1:
                if ftype == TType.BOOL:
                    self.success = iprot.readBool()
                else:
                    iprot.skip(ftype)
            elif fid == 2:
                if ftype == TType.STRING:
                    self.authToken = iprot.readString().decode('utf-8') if sys.version_info[0] == 2 else iprot.readString()
                else:
                    iprot.skip(ftype)
            else:
                iprot.skip(ftype)
            iprot.readFieldEnd()
        iprot.readStructEnd()

    def write(self, oprot):
        if oprot._fast_encode is not None and self.thrift_spec is not None:
            oprot.trans.write(oprot._fast_encode(self, [self.__class__, self.thrift_spec]))
            return
        oprot.writeStructBegin('TReturnLogonConnection')
        if self.success is not None:
            oprot.writeFieldBegin('success', TType.BOOL, 1)
            oprot.writeBool(self.success)
            oprot.writeFieldEnd()
        if self.authToken is not None:
            oprot.writeFieldBegin('authToken', TType.STRING, 2)
            oprot.writeString(self.authToken.encode('utf-8') if sys.version_info[0] == 2 else self.authToken)
            oprot.writeFieldEnd()
        oprot.writeFieldStop()
        oprot.writeStructEnd()

    def validate(self):
        return

    def __repr__(self):
        L = ['%s=%r' % (key, value)
             for key, value in self.__dict__.items()]
        return '%s(%s)' % (self.__class__.__name__, ', '.join(L))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not (self == other)
all_structs.append(TVersion)
TVersion.thrift_spec = (
    None,  # 0
    (1, TType.I32, 'VersionMajor', None, None, ),  # 1
    (2, TType.I32, 'VersionMinor', None, None, ),  # 2
)
all_structs.append(TSessionInfo)
TSessionInfo.thrift_spec = (
    None,  # 0
    (1, TType.I32, 'sessionId', None, None, ),  # 1
    (2, TType.STRING, 'winStationName', 'UTF8', None, ),  # 2
    (3, TType.I32, 'connectState', None, None, ),  # 3
)
all_structs.append(TReturnEnumerateSession)
TReturnEnumerateSession.thrift_spec = (
    None,  # 0
    (1, TType.BOOL, 'returnValue', None, None, ),  # 1
    (2, TType.LIST, 'sessionInfoList', (TType.STRUCT, [TSessionInfo, None], False), None, ),  # 2
)
all_structs.append(TReturnVirtualChannelOpen)
TReturnVirtualChannelOpen.thrift_spec = (
    None,  # 0
    (1, TType.STRING, 'pipeName', 'UTF8', None, ),  # 1
    (2, TType.I32, 'instance', None, None, ),  # 2
)
all_structs.append(TClientDisplay)
TClientDisplay.thrift_spec = (
    None,  # 0
    (1, TType.I32, 'displayWidth', None, None, ),  # 1
    (2, TType.I32, 'displayHeight', None, None, ),  # 2
    (3, TType.I32, 'colorDepth', None, None, ),  # 3
)
all_structs.append(TWTSINFO)
TWTSINFO.thrift_spec = (
    None,  # 0
    (1, TType.I32, 'State', None, None, ),  # 1
    (2, TType.I32, 'SessionId', None, None, ),  # 2
    (3, TType.I32, 'IncomingBytes', None, None, ),  # 3
    (4, TType.I32, 'OutgoingBytes', None, None, ),  # 4
    (5, TType.I32, 'IncomingFrames', None, None, ),  # 5
    (6, TType.I32, 'OutgoingFrames', None, None, ),  # 6
    (7, TType.I32, 'IncomingCompressedBytes', None, None, ),  # 7
    (8, TType.I32, 'OutgoingCompressedBytes', None, None, ),  # 8
    (9, TType.STRING, 'WinStationName', 'UTF8', None, ),  # 9
    (10, TType.STRING, 'Domain', 'UTF8', None, ),  # 10
    (11, TType.STRING, 'UserName', 'UTF8', None, ),  # 11
    (12, TType.I64, 'ConnectTime', None, None, ),  # 12
    (13, TType.I64, 'DisconnectTime', None, None, ),  # 13
    (14, TType.I64, 'LastInputTime', None, None, ),  # 14
    (15, TType.I64, 'LogonTime', None, None, ),  # 15
    (16, TType.I64, 'CurrentTime', None, None, ),  # 16
)
all_structs.append(TSessionInfoValue)
TSessionInfoValue.thrift_spec = (
    None,  # 0
    (1, TType.BOOL, 'boolValue', None, None, ),  # 1
    (2, TType.I16, 'int16Value', None, None, ),  # 2
    (3, TType.I32, 'int32Value', None, None, ),  # 3
    (4, TType.STRING, 'stringValue', 'UTF8', None, ),  # 4
    (5, TType.STRUCT, 'displayValue', [TClientDisplay, None], None, ),  # 5
    (6, TType.STRUCT, 'WTSINFO', [TWTSINFO, None], None, ),  # 6
    (7, TType.I64, 'int64Value', None, None, ),  # 7
)
all_structs.append(TReturnQuerySessionInformation)
TReturnQuerySessionInformation.thrift_spec = (
    None,  # 0
    (1, TType.BOOL, 'returnValue', None, None, ),  # 1
    (2, TType.STRUCT, 'infoValue', [TSessionInfoValue, None], None, ),  # 2
)
all_structs.append(TReturnLogonConnection)
TReturnLogonConnection.thrift_spec = (
    None,  # 0
    (1, TType.BOOL, 'success', None, None, ),  # 1
    (2, TType.STRING, 'authToken', 'UTF8', None, ),  # 2
)
fix_spec(all_structs)
del all_structs
