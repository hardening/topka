# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: SBP.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='SBP.proto',
  package='ogon.sbp',
  syntax='proto2',
  serialized_pb=_b('\n\tSBP.proto\x12\x08ogon.sbp\"G\n\x12VersionInfoRequest\x12\x11\n\tsessionId\x18\x01 \x02(\r\x12\x0e\n\x06vmajor\x18\x02 \x02(\r\x12\x0e\n\x06vminor\x18\x03 \x02(\r\"5\n\x13VersionInfoResponse\x12\x0e\n\x06vmajor\x18\x02 \x02(\r\x12\x0e\n\x06vminor\x18\x03 \x02(\r\"`\n\x17\x41uthenticateUserRequest\x12\x11\n\tsessionId\x18\x01 \x02(\r\x12\x10\n\x08username\x18\x02 \x02(\t\x12\x10\n\x08password\x18\x03 \x02(\t\x12\x0e\n\x06\x64omain\x18\x04 \x02(\t\"\xd2\x01\n\x18\x41uthenticateUserResponse\x12\x42\n\nauthStatus\x18\x01 \x02(\x0e\x32..ogon.sbp.AuthenticateUserResponse.AUTH_STATUS\"r\n\x0b\x41UTH_STATUS\x12\x13\n\x0f\x41UTH_SUCCESSFUL\x10\x00\x12\x18\n\x14\x41UTH_BAD_CREDENTIALS\x10\x01\x12\x1c\n\x18\x41UTH_WRONG_SESSION_STATE\x10\x02\x12\x16\n\x12\x41UTH_UNKNOWN_ERROR\x10\x03\"&\n\x11\x45ndSessionRequest\x12\x11\n\tsessionId\x18\x01 \x02(\r\"%\n\x12\x45ndSessionResponse\x12\x0f\n\x07success\x18\x01 \x02(\x08*C\n\x07MSGTYPE\x12\x15\n\x10\x41uthenticateUser\x10\xc8\x01\x12\x0f\n\nEndSession\x10\xc9\x01\x12\x10\n\x0bVersionInfo\x10\xca\x01')
)
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

_MSGTYPE = _descriptor.EnumDescriptor(
  name='MSGTYPE',
  full_name='ogon.sbp.MSGTYPE',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='AuthenticateUser', index=0, number=200,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='EndSession', index=1, number=201,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='VersionInfo', index=2, number=202,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=541,
  serialized_end=608,
)
_sym_db.RegisterEnumDescriptor(_MSGTYPE)

MSGTYPE = enum_type_wrapper.EnumTypeWrapper(_MSGTYPE)
AuthenticateUser = 200
EndSession = 201
VersionInfo = 202


_AUTHENTICATEUSERRESPONSE_AUTH_STATUS = _descriptor.EnumDescriptor(
  name='AUTH_STATUS',
  full_name='ogon.sbp.AuthenticateUserResponse.AUTH_STATUS',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='AUTH_SUCCESSFUL', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='AUTH_BAD_CREDENTIALS', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='AUTH_WRONG_SESSION_STATE', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='AUTH_UNKNOWN_ERROR', index=3, number=3,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=346,
  serialized_end=460,
)
_sym_db.RegisterEnumDescriptor(_AUTHENTICATEUSERRESPONSE_AUTH_STATUS)


_VERSIONINFOREQUEST = _descriptor.Descriptor(
  name='VersionInfoRequest',
  full_name='ogon.sbp.VersionInfoRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='sessionId', full_name='ogon.sbp.VersionInfoRequest.sessionId', index=0,
      number=1, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='vmajor', full_name='ogon.sbp.VersionInfoRequest.vmajor', index=1,
      number=2, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='vminor', full_name='ogon.sbp.VersionInfoRequest.vminor', index=2,
      number=3, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
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
  serialized_start=23,
  serialized_end=94,
)


_VERSIONINFORESPONSE = _descriptor.Descriptor(
  name='VersionInfoResponse',
  full_name='ogon.sbp.VersionInfoResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='vmajor', full_name='ogon.sbp.VersionInfoResponse.vmajor', index=0,
      number=2, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='vminor', full_name='ogon.sbp.VersionInfoResponse.vminor', index=1,
      number=3, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
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
  serialized_start=96,
  serialized_end=149,
)


_AUTHENTICATEUSERREQUEST = _descriptor.Descriptor(
  name='AuthenticateUserRequest',
  full_name='ogon.sbp.AuthenticateUserRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='sessionId', full_name='ogon.sbp.AuthenticateUserRequest.sessionId', index=0,
      number=1, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='username', full_name='ogon.sbp.AuthenticateUserRequest.username', index=1,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='password', full_name='ogon.sbp.AuthenticateUserRequest.password', index=2,
      number=3, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='domain', full_name='ogon.sbp.AuthenticateUserRequest.domain', index=3,
      number=4, type=9, cpp_type=9, label=2,
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
  serialized_start=151,
  serialized_end=247,
)


_AUTHENTICATEUSERRESPONSE = _descriptor.Descriptor(
  name='AuthenticateUserResponse',
  full_name='ogon.sbp.AuthenticateUserResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='authStatus', full_name='ogon.sbp.AuthenticateUserResponse.authStatus', index=0,
      number=1, type=14, cpp_type=8, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _AUTHENTICATEUSERRESPONSE_AUTH_STATUS,
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=250,
  serialized_end=460,
)


_ENDSESSIONREQUEST = _descriptor.Descriptor(
  name='EndSessionRequest',
  full_name='ogon.sbp.EndSessionRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='sessionId', full_name='ogon.sbp.EndSessionRequest.sessionId', index=0,
      number=1, type=13, cpp_type=3, label=2,
      has_default_value=False, default_value=0,
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
  serialized_start=462,
  serialized_end=500,
)


_ENDSESSIONRESPONSE = _descriptor.Descriptor(
  name='EndSessionResponse',
  full_name='ogon.sbp.EndSessionResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='success', full_name='ogon.sbp.EndSessionResponse.success', index=0,
      number=1, type=8, cpp_type=7, label=2,
      has_default_value=False, default_value=False,
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
  serialized_start=502,
  serialized_end=539,
)

_AUTHENTICATEUSERRESPONSE.fields_by_name['authStatus'].enum_type = _AUTHENTICATEUSERRESPONSE_AUTH_STATUS
_AUTHENTICATEUSERRESPONSE_AUTH_STATUS.containing_type = _AUTHENTICATEUSERRESPONSE
DESCRIPTOR.message_types_by_name['VersionInfoRequest'] = _VERSIONINFOREQUEST
DESCRIPTOR.message_types_by_name['VersionInfoResponse'] = _VERSIONINFORESPONSE
DESCRIPTOR.message_types_by_name['AuthenticateUserRequest'] = _AUTHENTICATEUSERREQUEST
DESCRIPTOR.message_types_by_name['AuthenticateUserResponse'] = _AUTHENTICATEUSERRESPONSE
DESCRIPTOR.message_types_by_name['EndSessionRequest'] = _ENDSESSIONREQUEST
DESCRIPTOR.message_types_by_name['EndSessionResponse'] = _ENDSESSIONRESPONSE
DESCRIPTOR.enum_types_by_name['MSGTYPE'] = _MSGTYPE

VersionInfoRequest = _reflection.GeneratedProtocolMessageType('VersionInfoRequest', (_message.Message,), dict(
  DESCRIPTOR = _VERSIONINFOREQUEST,
  __module__ = 'SBP_pb2'
  # @@protoc_insertion_point(class_scope:ogon.sbp.VersionInfoRequest)
  ))
_sym_db.RegisterMessage(VersionInfoRequest)

VersionInfoResponse = _reflection.GeneratedProtocolMessageType('VersionInfoResponse', (_message.Message,), dict(
  DESCRIPTOR = _VERSIONINFORESPONSE,
  __module__ = 'SBP_pb2'
  # @@protoc_insertion_point(class_scope:ogon.sbp.VersionInfoResponse)
  ))
_sym_db.RegisterMessage(VersionInfoResponse)

AuthenticateUserRequest = _reflection.GeneratedProtocolMessageType('AuthenticateUserRequest', (_message.Message,), dict(
  DESCRIPTOR = _AUTHENTICATEUSERREQUEST,
  __module__ = 'SBP_pb2'
  # @@protoc_insertion_point(class_scope:ogon.sbp.AuthenticateUserRequest)
  ))
_sym_db.RegisterMessage(AuthenticateUserRequest)

AuthenticateUserResponse = _reflection.GeneratedProtocolMessageType('AuthenticateUserResponse', (_message.Message,), dict(
  DESCRIPTOR = _AUTHENTICATEUSERRESPONSE,
  __module__ = 'SBP_pb2'
  # @@protoc_insertion_point(class_scope:ogon.sbp.AuthenticateUserResponse)
  ))
_sym_db.RegisterMessage(AuthenticateUserResponse)

EndSessionRequest = _reflection.GeneratedProtocolMessageType('EndSessionRequest', (_message.Message,), dict(
  DESCRIPTOR = _ENDSESSIONREQUEST,
  __module__ = 'SBP_pb2'
  # @@protoc_insertion_point(class_scope:ogon.sbp.EndSessionRequest)
  ))
_sym_db.RegisterMessage(EndSessionRequest)

EndSessionResponse = _reflection.GeneratedProtocolMessageType('EndSessionResponse', (_message.Message,), dict(
  DESCRIPTOR = _ENDSESSIONRESPONSE,
  __module__ = 'SBP_pb2'
  # @@protoc_insertion_point(class_scope:ogon.sbp.EndSessionResponse)
  ))
_sym_db.RegisterMessage(EndSessionResponse)


# @@protoc_insertion_point(module_scope)
