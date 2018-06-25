# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: pbRPC.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='pbRPC.proto',
  package='ogon.pbrpc',
  syntax='proto2',
  serialized_pb=_b('\n\x0bpbRPC.proto\x12\nogon.pbrpc\"=\n\x0bVersionInfo\x12\x0e\n\x06vmajor\x18\x01 \x02(\r\x12\x0e\n\x06vminor\x18\x02 \x02(\r\x12\x0e\n\x06\x63ookie\x18\x03 \x01(\t\"\x87\x02\n\x07RPCBase\x12\x0b\n\x03tag\x18\x01 \x02(\r\x12\x19\n\nisResponse\x18\x02 \x02(\x08:\x05\x66\x61lse\x12\x36\n\x06status\x18\x03 \x02(\x0e\x32\x1d.ogon.pbrpc.RPCBase.RPCSTATUS:\x07SUCCESS\x12\x0f\n\x07msgType\x18\x04 \x02(\r\x12\x0f\n\x07payload\x18\x05 \x01(\x0c\x12\x18\n\x10\x65rrorDescription\x18\x06 \x01(\t\x12,\n\x0bversionInfo\x18\x07 \x01(\x0b\x32\x17.ogon.pbrpc.VersionInfo\"2\n\tRPCSTATUS\x12\x0b\n\x07SUCCESS\x10\x00\x12\n\n\x06\x46\x41ILED\x10\x01\x12\x0c\n\x08NOTFOUND\x10\x02')
)
_sym_db.RegisterFileDescriptor(DESCRIPTOR)



_RPCBASE_RPCSTATUS = _descriptor.EnumDescriptor(
  name='RPCSTATUS',
  full_name='ogon.pbrpc.RPCBase.RPCSTATUS',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='SUCCESS', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='FAILED', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='NOTFOUND', index=2, number=2,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=304,
  serialized_end=354,
)
_sym_db.RegisterEnumDescriptor(_RPCBASE_RPCSTATUS)


_VERSIONINFO = _descriptor.Descriptor(
  name='VersionInfo',
  full_name='ogon.pbrpc.VersionInfo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='vmajor', full_name='ogon.pbrpc.VersionInfo.vmajor', index=0,
      number=1, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='vminor', full_name='ogon.pbrpc.VersionInfo.vminor', index=1,
      number=2, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='cookie', full_name='ogon.pbrpc.VersionInfo.cookie', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=27,
  serialized_end=88,
)


_RPCBASE = _descriptor.Descriptor(
  name='RPCBase',
  full_name='ogon.pbrpc.RPCBase',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='tag', full_name='ogon.pbrpc.RPCBase.tag', index=0,
      number=1, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='isResponse', full_name='ogon.pbrpc.RPCBase.isResponse', index=1,
      number=2, type=8, cpp_type=7, label=2,
      has_default_value=True, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='status', full_name='ogon.pbrpc.RPCBase.status', index=2,
      number=3, type=14, cpp_type=8, label=2,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='msgType', full_name='ogon.pbrpc.RPCBase.msgType', index=3,
      number=4, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='payload', full_name='ogon.pbrpc.RPCBase.payload', index=4,
      number=5, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='errorDescription', full_name='ogon.pbrpc.RPCBase.errorDescription', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='versionInfo', full_name='ogon.pbrpc.RPCBase.versionInfo', index=6,
      number=7, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _RPCBASE_RPCSTATUS,
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=91,
  serialized_end=354,
)

_RPCBASE.fields_by_name['status'].enum_type = _RPCBASE_RPCSTATUS
_RPCBASE.fields_by_name['versionInfo'].message_type = _VERSIONINFO
_RPCBASE_RPCSTATUS.containing_type = _RPCBASE
DESCRIPTOR.message_types_by_name['VersionInfo'] = _VERSIONINFO
DESCRIPTOR.message_types_by_name['RPCBase'] = _RPCBASE

VersionInfo = _reflection.GeneratedProtocolMessageType('VersionInfo', (_message.Message,), dict(
  DESCRIPTOR = _VERSIONINFO,
  __module__ = 'pbRPC_pb2'
  # @@protoc_insertion_point(class_scope:ogon.pbrpc.VersionInfo)
  ))
_sym_db.RegisterMessage(VersionInfo)

RPCBase = _reflection.GeneratedProtocolMessageType('RPCBase', (_message.Message,), dict(
  DESCRIPTOR = _RPCBASE,
  __module__ = 'pbRPC_pb2'
  # @@protoc_insertion_point(class_scope:ogon.pbrpc.RPCBase)
  ))
_sym_db.RegisterMessage(RPCBase)


# @@protoc_insertion_point(module_scope)