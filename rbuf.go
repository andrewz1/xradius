package xradius

import (
	"encoding/binary"
	"errors"
	"sync"
)

type rBuf struct {
	bb []byte // buffer data
	bp int    // buffer pointer
	bl int    // buffer left
}

var (
	errNoData      = errors.New("no data")
	errInvalidData = errors.New("invalid attr data")
	rbPool         sync.Pool
)

func rbGet(src []byte) (rb *rBuf) {
	if v := rbPool.Get(); v != nil {
		rb = v.(*rBuf)
		if cap(rb.bb) < len(src) { // resize buffer
			rb.bb = make([]byte, len(src))
		} else {
			rb.bb = rb.bb[:len(src)]
		}
		rb.bl = len(src)
	} else {
		rb = &rBuf{
			bb: make([]byte, len(src)),
			bl: len(src),
		}
	}
	copy(rb.bb, src)
	return
}

func rbPut(rb *rBuf) {
	if rb == nil {
		return
	}
	rb.bb = rb.bb[:0]
	rb.bp = 0
	rb.bl = 0
	rbPool.Put(rb)
}

func rbNew(src []byte) *rBuf {
	return &rBuf{
		bb: src,
		bl: len(src),
	}
}

func (rb *rBuf) left() int {
	return rb.bl
}

func (rb *rBuf) getSlice(ln int) (out []byte, err error) {
	if rb.bl < ln {
		err = errNoData
		return
	}
	out = rb.bb[rb.bp : rb.bp+ln]
	rb.bp += ln
	rb.bl -= ln
	return
}

func (rb *rBuf) getByte() (out byte, err error) {
	if rb.bl < 1 {
		err = errNoData
		return
	}
	out = rb.bb[rb.bp]
	rb.bp++
	rb.bl--
	return
}

func (rb *rBuf) getUInt16() (out uint16, err error) {
	if rb.bl < 2 {
		err = errNoData
		return
	}
	out = binary.BigEndian.Uint16(rb.bb[rb.bp:])
	rb.bp += 2
	rb.bl -= 2
	return
}

func (rb *rBuf) getUInt32() (out uint32, err error) {
	if rb.bl < 4 {
		err = errNoData
		return
	}
	out = binary.BigEndian.Uint32(rb.bb[rb.bp:])
	rb.bp += 4
	rb.bl -= 4
	return
}

func (rb *rBuf) getAttr() (t, l byte, v []byte, err error) {
	bp := rb.bp
	bl := rb.bl
	defer func() {
		if err != nil { // restore buffer state on error
			rb.bp = bp
			rb.bl = bl
		}
	}()
	if t, err = rb.getByte(); err != nil {
		return
	}
	if l, err = rb.getByte(); err != nil {
		return
	}
	sl := int(l) - 2
	if sl < 0 {
		err = errInvalidData
		return
	} else if sl == 0 {
		return
	}
	v, err = rb.getSlice(sl)
	return
}
