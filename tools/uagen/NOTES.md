# uagen Notes & UA-Nodeset Schema Analysis

## 1. Schema Inputs

Inputs vendored from OPCFoundation/UA-Nodeset (MIT licence):
- Commit: `2cfb50aba4e0fad4adfaebe987876406abf2bd3a`
- Source repository: `https://github.com/OPCFoundation/UA-Nodeset`
- Files:
  - `schema/Opc.Ua.Types.bsd`
  - `schema/NodeIds.csv`
  - `schema/StatusCode.csv`
  - `schema/UA-Nodeset-LICENSE`
  - `schema/SOURCE.txt`

## 2. Type Counts & Statistics

Analysis of `schema/Opc.Ua.Types.bsd`:
- StructuredTypes: 372
- EnumeratedTypes: 69
- OpaqueTypes: 30
- Total types defined in schema: 471

## 3. Distinct Field Attributes

The following distinct attributes appear on `opc:Field` elements in `Opc.Ua.Types.bsd`:
1. `Name`: Symbolic field name.
2. `TypeName`: Field data type identifier (prefixed with `opc:`, `ua:`, or `tns:`).
3. `LengthField`: Identifies the preceding array length field (consumed per C201, never emitted as struct member).
4. `SourceType`: Indicates inherited fields from parent types (present on 94 fields).
5. `SwitchField`: Selector field for switch/optional fields and unions.
6. `SwitchValue`: Selector value for switch/optional fields.
7. `Length`: Bit-field length for packed bit fields.

### Deviations from DESIGN 8.1:
- `Terminator`: DESIGN 8.1 lists `Terminator` as a field attribute; in the pinned UA-Nodeset schema, no field uses `Terminator`.
- `SourceType`: DESIGN 8.1 does not mention `SourceType`; 94 fields have `SourceType` pointing to base configuration records or parent types.
- Non-ExtensionObject Base Types: 12 structured types have a `BaseType` other than `ua:ExtensionObject` (e.g. `tns:Vector`, `tns:NodeAttributes`, `tns:BaseConfigurationRecordDataType`).
- Bit-field Enums: `NodeIdType` specifies `LengthInBits="6"` rather than a byte-aligned size.

## 4. Unsupported Constructs Breakdown

Types with unsupported constructs in v1:
- Switch/union/optional fields: 58 fields use `SwitchField`, 37 use `SwitchValue` (e.g., `NodeId`, `ExpandedNodeId`, `DiagnosticInfo`, `LocalizedText`, `DataValue`, `ExtensionObject`, `Variant`). Hand-written in v1 built-in types.
- Fixed bit fields: 8 fields use `Length` without `LengthField` (e.g., `VariantType`, `ArrayDimensionsSpecified`).
- Non-standard enum length: `NodeIdType` (6 bits).
- Base type deviations: 12 structured types inheriting from non-ExtensionObject bases.
- Opaque types: 30 types defined as `opc:OpaqueType`, mapped to hand-written built-in types.

All unsupported constructs fail hard (C202) if encountered in the generation closure, never guessed.

## 5. Roots Whitelist and Transitive Closure

Roots (38 types from DESIGN 8.2 and M4a step 4, defined in `tools/uagen/roots.txt`):
- Discovery: `GetEndpointsRequest/Response`, `FindServersRequest/Response`, `FindServersOnNetworkRequest/Response`
- Session: `CreateSessionRequest/Response`, `ActivateSessionRequest/Response`, `CloseSessionRequest/Response`
- SecureChannel: `OpenSecureChannelRequest/Response`, `CloseSecureChannelRequest/Response`, `ChannelSecurityToken`
- Browse: `BrowseRequest/Response`, `BrowseNextRequest/Response`
- Translate: `TranslateBrowsePathsToNodeIdsRequest/Response`
- Services: `ReadRequest/Response`, `WriteRequest/Response`, `CallRequest/Response`
- Headers & Faults: `RequestHeader`, `ResponseHeader`, `ServiceFault`
- Identity & Auth: `AnonymousIdentityToken`, `UserNameIdentityToken`, `SignatureData`, `SignedSoftwareCertificate`
- Metadata & Values: `Argument`, `EnumValueType`

### Transitive Closure Result:
- Total closure types: **62** (53 StructuredTypes, 9 EnumeratedTypes).
- Well within acceptance requirement (between 50 and 120 names).
- Verified inclusion of required acceptance types:
  - `ReadRequest`: present (StructuredType)
  - `BrowseResult`: present (StructuredType)
  - `EndpointDescription`: present (StructuredType)
  - `Argument`: present (StructuredType)
- All 62 closure types are valid ExtensionObject-based structured types or standard 32-bit enums; 0 unsupported constructs within the closure.

## 6. NodeIds Verification

- `ReadRequest_Encoding_DefaultBinary`: **631** (verified against `schema/NodeIds.csv`).
