package xradius

type RadiusCode byte

// RFC constants
const (
	AccessRequest      RadiusCode = 1
	AccessAccept       RadiusCode = 2
	AccessReject       RadiusCode = 3
	AccountingRequest  RadiusCode = 4
	AccountingResponse RadiusCode = 5
	AccountingStatus   RadiusCode = 6
	PasswordRequest    RadiusCode = 7
	PasswordAck        RadiusCode = 8
	PasswordReject     RadiusCode = 9
	AccountingMessage  RadiusCode = 10
	AccessChallenge    RadiusCode = 11
	StatusServer       RadiusCode = 12
	StatusClient       RadiusCode = 13
	DisconnectRequest  RadiusCode = 40
	DisconnectACK      RadiusCode = 41
	DisconnectNAK      RadiusCode = 42
	CoARequest         RadiusCode = 43
	CoAACK             RadiusCode = 44
	CoANAK             RadiusCode = 45
)

const (
	PacketMinLen = 20   // Min packet len
	PacketMaxLen = 4096 // Max packet len
)

type Packet struct {
	code   RadiusCode  // Radius packet code
	id     byte        // Packet ID
	len    uint16      // Packet len
	auth   []byte      // Auth data
	attrs  []*Attr     // Attr slice
	vids   []VendorID  // Vendor IDs form packet
	secret []byte      // Radius shared secret
	data   []byte      // Raw packet data
	udata  interface{} // User data
	reply  bool        // Is this reply
}
