package xradius

import (
	"encoding/binary"
	"errors"
)

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

	AuthLen  = 16 // Auth data len
	AttrsCap = 32 // Alloc space for attrs for append
)

type Packet struct {
	code   RadiusCode  // Radius packet code
	id     byte        // Packet ID
	len    uint16      // Packet len
	auth   []byte      // Auth data
	attrs  []*Attr     // Attr slice
	vids   []VendorID  // Vendor IDs form packet
	secret []byte      // Radius shared secret
	data   *rBuf       // Raw packet data
	udata  interface{} // User data
	reply  bool        // Is this reply
}

func ParsePacket(buf []byte) (pkt *Packet, err error) {
	if len(buf) < PacketMinLen {
		err = errors.New("Packet too short")
		return
	}
	pLen := binary.BigEndian.Uint16(buf[2:])
	if pLen < PacketMinLen || pLen > PacketMaxLen || int(pLen) > len(buf) {
		err = errors.New("Packet len error")
		return
	}
	pkt = &Packet{
		attrs: make([]*Attr, 0, AttrsCap),
		data:  rbGet(buf),
	}
	defer func() {
		if err != nil {
			for _, a := range pkt.attrs { // remove cross ref
				a.pkt = nil
			}
			rbPut(pkt.data)
		}
	}()
	v, _ := pkt.data.getByte()
	pkt.code = RadiusCode(v)
	pkt.id, _ = pkt.data.getByte()
	pkt.auth, _ = pkt.data.getSlice(AuthLen)
	vm := make(map[VendorID]struct{})
	for pkt.data.left() >= 2 {
		var (
			t, l, vt, vl byte
			v, vv        []byte
			vid          uint32
		)
		if t, l, v, err = pkt.data.getAttr(); err != nil {
			return
		}
		if AttrType(t) != AttrVSA {
			ad := GetAttrByAttr(AttrType(t))
			tag := byte(0)
			if ad.IsTagged() && len(v) > 0 {
				tag = v[0]
				v = v[1:]
			}
			a := &Attr{
				atype: AttrType(t),
				alen:  l,
				tag:   tag,
				data:  v,
				ad:    ad,
				pkt:   pkt,
			}
			pkt.attrs = append(pkt.attrs, a)
		} else {
			rb := rbNew(v)
			if vid, err = rb.getUInt32(); err != nil {
				return
			}
			vm[VendorID(vid)] = struct{}{}
			for rb.left() >= 2 {
				if vt, vl, vv, err = rb.getAttr(); err != nil {
					return
				}
				ad := GetVSAByAttr(VendorID(vid), VendorType(vt))
				tag := byte(0)
				if ad.IsTagged() && len(vv) > 0 {
					tag = vv[0]
					vv = vv[1:]
				}
				a := &Attr{
					atype: AttrVSA,
					alen:  vl + 6,
					vid:   VendorID(vid),
					vtype: VendorType(vt),
					vlen:  vl,
					tag:   tag,
					data:  vv,
					ad:    ad,
					pkt:   pkt,
				}
				pkt.attrs = append(pkt.attrs, a)
			}
		}
	}
	pkt.vids = make([]VendorID, 0, len(vm))
	for k := range vm {
		pkt.vids = append(pkt.vids, k)
	}
	return
}
