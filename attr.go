package xradius

type AttrType byte   // Attr type
type VendorID uint32 // Vendor ID for VSA
type VendorType byte // Vendor type for VSA

const AttrVSA AttrType = 26

// Attr encryption
type AttrEnc int

const (
	AttrEncNone AttrEnc = iota // No encryption
	AttrEncUsr                 // User-Password encryption
	AttrEncTun                 // Tunnel-Password encryption
	AttrEncAsc                 // Ascend’s proprietary encryption
)

// Attr data type
type AttrDType int

const (
	DTypeRaw     AttrDType = iota // []byte any unknown attr
	DTypeInt                      // uint32 rfc8044 tag 1
	DTypeEnum                     // uint32 rfc8044 tag 2
	DTypeTime                     // uint32 rfc8044 tag 3
	DTypeText                     // []byte rfc8044 tag 4
	DTypeString                   // []byte rfc8044 tag 5
	DTypeConcat                   // []byte rfc8044 tag 6
	DTypeIfID                     // [8]byte rfc8044 tag 7
	DTypeIP4                      // [4]byte rfc8044 tag 8
	DTypeIP6                      // [16]byte rfc8044 tag 9
	DTypeIP6Pfx                   // [18]byte rfc8044 tag 10
	DTypeIP4Pfx                   // [6]byte rfc8044 tag 11
	DTypeInt64                    // uint64 rfc8044 tag 12
	DTypeTLV                      // []byte rfc8044 tag 13
	DTypeVSA                      // []byte rfc8044 tag 14
	DTypeEXT                      // []byte rfc8044 tag 15
	DTypeLongEXT                  // []byte rfc8044 tag 16
	DTypeEVS                      // []byte rfc8044 tag 17
	DTypeIP                       // []byte ip4 or ip6 addr (len depend)
	DTypeByte                     // byte
	DTypeEth                      // [6]byte MAC
	DTypeShort                    // uint16
	DTypeSInt                     // int32
)

type Attr struct {
	atype AttrType    // Attr type
	alen  byte        // Attr len
	vid   VendorID    // Vendor ID
	vtype VendorType  // Vendor Type
	vlen  byte        // Vendor len
	tag   byte        // Tag for tagged attrs
	data  []byte      // Raw attr data without tag
	edata interface{} // Evaluated data
	ad    *AttrData   // Attribute data from dict
	pkt   *Packet     // Packet which this attr is belongs
}

type AttrData struct {
	name   string
	atype  AttrType
	vid    VendorID
	vtype  VendorType
	dtype  AttrDType
	enc    AttrEnc
	tagged bool
}

func (ad *AttrData) IsTagged() bool {
	if ad == nil {
		return false // default is untagged
	}
	return ad.tagged
}

func (ad *AttrData) GetEnc() AttrEnc {
	if ad == nil {
		return AttrEncNone
	}
	return ad.enc
}

func (ad *AttrData) GetName() string {
	if ad == nil {
		return ""
	}
	return ad.name
}

func (ad *AttrData) GetDataType() AttrDType {
	if ad == nil {
		return DTypeRaw
	}
	return ad.dtype
}
