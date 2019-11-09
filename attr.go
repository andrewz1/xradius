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
	DTypeRaw    AttrDType = iota // byte slice
	DTypeString                  // string
	DTypeIP4                     // ip addr
	DTypeIP4Pfx                  // 6 bytes
	DTypeInt                     // uint32
	DTypeInt64                   // uint64
	DTypeDate                    // unix time 32 bit
	DTypeIfID                    // 8 bytes
	DTypeIP6                     // 16 bytes
	DTypeIP6Pfx                  // 18 bytes
	DTypeByte                    // one byte
	DTypeEth                     // 6 bytes, MAC
	DTypeShort                   // uint16
	DTypeSInt                    // signed int
	DTypeVSA                     // VSA
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
