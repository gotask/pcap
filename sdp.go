// sdp.go
package main

import (
	"errors"
	"io"
	"reflect"
	"strconv"
	"unsafe"
)

var (
	errNoEnoughData = errors.New("NoEnoughData")
	errOverflow     = errors.New("integer overflow")
	errInvalidType  = errors.New("invalid type")
	errStructEnd    = errors.New("struct end")
	errNeedPtr      = errors.New("ptr is needed")
)

type Sdp struct {
	buf   []byte // encode/decode byte stream
	index int    // write/read point
}

const (
	SdpPackDataType_Integer_Positive = 0
	SdpPackDataType_Integer_Negative = 1
	SdpPackDataType_Float            = 2
	SdpPackDataType_Double           = 3
	SdpPackDataType_String           = 4
	SdpPackDataType_Vector           = 5
	SdpPackDataType_Map              = 6
	SdpPackDataType_StructBegin      = 7
	SdpPackDataType_StructEnd        = 8
)

func (sdp *Sdp) packData(data []byte) {
	sdp.buf = append(sdp.buf, data...)
}

func (sdp *Sdp) packByte(x byte) {
	sdp.buf = append(sdp.buf, x)
}

func (sdp *Sdp) packNumber(x uint64) {
	for x >= 1<<7 {
		sdp.buf = append(sdp.buf, uint8(x&0x7f|0x80))
		x >>= 7
	}
	sdp.buf = append(sdp.buf, uint8(x))
}

func (sdp *Sdp) packHeader(tag uint32, typ uint8) {
	header := typ << 4
	if tag < 15 {
		header = header | uint8(tag)
		sdp.packByte(byte(header))
	} else {
		header = header | 0xf
		sdp.packByte(byte(header))
		sdp.packNumber(uint64(tag))
	}
}

func (sdp *Sdp) packSlice(tag uint32, x interface{}, packHead bool, require bool) error {
	if reflect.TypeOf(x).Kind() != reflect.Slice {
		return errInvalidType
	}
	refVal := reflect.ValueOf(x)
	if refVal.Len() == 0 && !require {
		return nil
	}
	sdp.packHeader(tag, SdpPackDataType_Vector)
	sdp.packNumber(uint64(refVal.Len()))
	for i := 0; i < refVal.Len(); i++ {
		err := sdp.pack(0, refVal.Index(i).Interface(), true, true)
		if err != nil {
			return err
		}
	}
	return nil
}

func (sdp *Sdp) packMap(tag uint32, x interface{}, packHead bool, require bool) error {
	if reflect.TypeOf(x).Kind() != reflect.Map {
		return errInvalidType
	}
	refVal := reflect.ValueOf(x)
	if refVal.Len() == 0 && !require {
		return nil
	}
	sdp.packHeader(tag, SdpPackDataType_Map)
	sdp.packNumber(uint64(refVal.Len()))
	keys := refVal.MapKeys()
	for i := 0; i < len(keys); i++ {
		err := sdp.pack(0, keys[i].Interface(), true, true)
		if err != nil {
			return err
		}
		err = sdp.pack(0, refVal.MapIndex(keys[i]).Interface(), true, true)
		if err != nil {
			return err
		}
	}
	return nil
}

func (sdp *Sdp) packStruct(tag uint32, x interface{}, packHead bool) error {
	if reflect.TypeOf(x).Kind() != reflect.Struct {
		return errInvalidType
	}
	refVal := reflect.ValueOf(x)
	sdp.packHeader(tag, SdpPackDataType_StructBegin)
	for i := 0; i < refVal.NumField(); i++ {
		iTg := i
		tg := refVal.Type().Field(i).Tag.Get("tag")
		if tg != "" {
			itg, er := strconv.Atoi(tg)
			if er == nil {
				iTg = itg
			}
		}
		req := refVal.Type().Field(i).Tag.Get("require")
		require := false
		if req == "true" {
			require = true
		}
		fld := refVal.Field(i)
		err := sdp.pack(uint32(iTg), fld.Interface(), true, require)
		if err != nil {
			return err
		}
	}
	sdp.packHeader(0, SdpPackDataType_StructEnd)
	return nil
}

func (sdp *Sdp) pack(tag uint32, x interface{}, packHead bool, require bool) error {
	typ := SdpPackDataType_Integer_Positive
	var val uint64

	switch reflect.TypeOf(x).Kind() {
	case reflect.Bool:
		{
			v := x.(bool)
			if v {
				val = 1
			}
		}
	case reflect.Int:
		{
			v := x.(int)
			if v < 0 {
				typ = SdpPackDataType_Integer_Negative
				v = -v
			}
			val = uint64(v)
		}
	case reflect.Int8:
		{
			v := x.(int8)
			if v < 0 {
				typ = SdpPackDataType_Integer_Negative
				v = -v
			}
			val = uint64(v)
		}
	case reflect.Int16:
		{
			v := x.(int16)
			if v < 0 {
				typ = SdpPackDataType_Integer_Negative
				v = -v
			}
			val = uint64(v)
		}
	case reflect.Int32:
		{
			v := x.(int32)
			if v < 0 {
				typ = SdpPackDataType_Integer_Negative
				v = -v
			}
			val = uint64(v)
		}
	case reflect.Int64:
		{
			v := x.(int64)
			if v < 0 {
				typ = SdpPackDataType_Integer_Negative
				v = -v
			}
			val = uint64(v)
		}
	case reflect.Uint:
		{
			v := x.(uint)
			val = uint64(v)
		}
	case reflect.Uint8:
		{
			v := x.(uint8)
			val = uint64(v)
		}
	case reflect.Uint16:
		{
			v := x.(uint16)
			val = uint64(v)
		}
	case reflect.Uint32:
		{
			v := x.(uint32)
			val = uint64(v)
		}
	case reflect.Uint64:
		{
			v := x.(uint64)
			val = uint64(v)
		}
	case reflect.Float32:
		{
			v := x.(float32)
			val = uint64(*(*uint32)(unsafe.Pointer(&v)))
		}
	case reflect.Float64:
		{
			v := x.(float64)
			val = uint64(*(*uint64)(unsafe.Pointer(&v)))
		}
	case reflect.String:
		{
			v := x.(string)
			if len(v) == 0 && !require {
				return nil
			}
			if packHead {
				sdp.packHeader(tag, SdpPackDataType_String)
			}
			sdp.packNumber(uint64(len(v)))
			sdp.packData(*(*[]byte)(unsafe.Pointer(&v)))
			return nil
		}
	case reflect.Slice:
		{
			return sdp.packSlice(tag, x, packHead, require)
		}
	case reflect.Map:
		{
			return sdp.packMap(tag, x, packHead, require)
		}
	case reflect.Struct:
		{
			return sdp.packStruct(tag, x, packHead)
		}
	default:
		{
			return errInvalidType
		}
	}

	if val == 0 && !require {
		return nil
	}

	if packHead {
		sdp.packHeader(tag, uint8(typ))
	}
	sdp.packNumber(val)
	return nil
}

func (sdp *Sdp) unpackByte(n int) (x []byte, err error) {
	if n <= 0 {
		return nil, nil
	}
	if sdp.index+n > len(sdp.buf) {
		return nil, errNoEnoughData
	}
	x = make([]byte, n, n)
	copy(x, sdp.buf[sdp.index:sdp.index+n])
	sdp.index = sdp.index + n
	return
}

func (sdp *Sdp) unpackNumber() (x uint64, err error) {
	// x, err already 0

	i := sdp.index
	l := len(sdp.buf)

	for shift := uint(0); shift < 64; shift += 7 {
		if i >= l {
			err = io.ErrUnexpectedEOF
			return
		}
		b := sdp.buf[i]
		i++
		x |= (uint64(b) & 0x7F) << shift
		if b < 0x80 {
			sdp.index = i
			return
		}
	}

	// The number is too large to represent in a 64-bit value.
	err = errOverflow
	return
}

func (sdp *Sdp) unpackHeader() (tag uint32, typ uint8, err error) {
	if len(sdp.buf) <= sdp.index {
		return 0, 0, errNoEnoughData
	}
	typ = sdp.buf[sdp.index] >> 4
	tag = uint32(sdp.buf[sdp.index] & 0xf)
	sdp.index++
	if tag == 0xf {
		tag1, err1 := sdp.unpackNumber()
		return uint32(tag1), typ, err1
	}
	return
}

func CanSetBool(x reflect.Value) bool {
	if !x.CanSet() {
		return false
	}
	switch k := x.Kind(); k {
	default:
		return false
	case reflect.Bool:
		return true
	}
	return false
}

func CanSetFloat(x reflect.Value) bool {
	if !x.CanSet() {
		return false
	}
	switch k := x.Kind(); k {
	default:
		return false
	case reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

func CanSetInt(x reflect.Value) bool {
	if !x.CanSet() {
		return false
	}
	switch k := x.Kind(); k {
	default:
		return false
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	}
	return false
}

func CanSetUint(x reflect.Value) bool {
	if !x.CanSet() {
		return false
	}
	switch k := x.Kind(); k {
	default:
		return false
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	}
	return false
}

func (sdp *Sdp) skipHeadField() {
	_, typ, err := sdp.unpackHeader()
	if err != nil {
		return
	}
	sdp.skipField(typ)
}

func (sdp *Sdp) skipField(typ uint8) {
	switch typ {
	case SdpPackDataType_Integer_Positive, SdpPackDataType_Integer_Negative, SdpPackDataType_Float, SdpPackDataType_Double:
		{
			sdp.unpackNumber()
		}
	case SdpPackDataType_String:
		{
			ln, err := sdp.unpackNumber()
			if err != nil {
				return
			}
			sdp.unpackByte(int(ln))
		}
	case SdpPackDataType_Vector:
		{
			ln, err := sdp.unpackNumber()
			if err != nil {
				return
			}
			for i := 0; i < int(ln); i++ {
				sdp.skipHeadField()
			}
		}
	case SdpPackDataType_Map:
		{
			ln, err := sdp.unpackNumber()
			if err != nil {
				return
			}
			for i := 0; i < int(ln); i++ {
				sdp.skipHeadField()
				sdp.skipHeadField()
			}
		}
	case SdpPackDataType_StructBegin:
		{
			sdp.skipToStructEnd()
		}
	case SdpPackDataType_StructEnd:
		{
			break
		}
	default:
		return
	}
}

func (sdp *Sdp) skipToStructEnd() {
	for {
		_, typ, err := sdp.unpackHeader()
		if err != nil {
			return
		}
		if typ == SdpPackDataType_StructEnd {
			break
		}
		sdp.skipField(typ)
	}
}

func (sdp *Sdp) unpack(x reflect.Value, first bool) error {
	if sdp.index >= len(sdp.buf) {
		return errNoEnoughData
	}

	tag, typ, err := sdp.unpackHeader()
	if err != nil {
		return err
	}

	var valField reflect.Value
	if x.Type().Kind() == reflect.Struct {
		isTag := false
		for i := 0; i < x.NumField(); i++ {
			tg := x.Type().Field(i).Tag.Get("tag")
			if tg != "" {
				iTg, er := strconv.Atoi(tg)
				if er == nil && iTg == int(tag) {
					valField = x.Field(i)
					isTag = true
					break
				}
			}
		}

		if !isTag {
			t := int(tag)
			if t < x.NumField() {
				tg := x.Type().Field(t).Tag.Get("tag")
				if tg == "" {
					valField = x.Field(t)
				}
			}
		}
	}

	switch typ {
	case SdpPackDataType_Integer_Positive:
		{
			v, err := sdp.unpackNumber()
			if err != nil {
				return err
			}

			if first {
				if CanSetUint(x) {
					x.SetUint(v)
				} else if CanSetInt(x) {
					x.SetInt(int64(v))
				} else if CanSetBool(x) {
					x.SetBool(v > 0)
				}
			} else {
				if CanSetUint(valField) {
					valField.SetUint(v)
				} else if CanSetInt(valField) {
					valField.SetInt(int64(v))
				} else if CanSetBool(valField) {
					valField.SetBool(v > 0)
				}
			}
		}
	case SdpPackDataType_Integer_Negative:
		{
			v, err := sdp.unpackNumber()
			if err != nil {
				return err
			}
			vv := int64(-v)

			if first {
				if CanSetInt(x) {
					x.SetInt(vv)
				}
			} else if CanSetInt(valField) {
				valField.SetInt(vv)
			}
		}
	case SdpPackDataType_Float, SdpPackDataType_Double:
		{
			v, err := sdp.unpackNumber()
			if err != nil {
				return err
			}
			f := *(*float64)(unsafe.Pointer(&v))
			if first {
				if CanSetFloat(x) {
					x.SetFloat(f)
				}
			} else if CanSetFloat(valField) {
				valField.SetFloat(f)
			}
		}
	case SdpPackDataType_String:
		{
			ln, err := sdp.unpackNumber()
			if err != nil {
				return err
			}
			bt, er := sdp.unpackByte(int(ln))
			if er != nil {
				return er
			}
			str := string(bt)
			if first {
				if x.Kind() == reflect.String {
					x.SetString(str)
				}
			} else if valField.Kind() == reflect.String {
				valField.SetString(str)
			}
		}
	case SdpPackDataType_Vector:
		{
			ln, err := sdp.unpackNumber()
			if err != nil {
				return err
			}
			var vecType reflect.Type
			if first {
				if x.Kind() == reflect.Slice && x.CanSet() {
					x.SetLen(0)
					vecType = x.Type().Elem()
				}
			} else if valField.Kind() == reflect.Slice && valField.CanSet() {
				valField.SetLen(0)
				vecType = valField.Type().Elem()
			}

			if vecType == nil {
				for i := 0; i < int(ln); i++ {
					sdp.skipHeadField()
				}
				break
			}

			vals := make([]reflect.Value, 0, ln)
			for i := 0; i < int(ln); i++ {
				vecVal := newValByType(vecType)
				err := sdp.unpack(vecVal, true)
				if err != nil {
					return err
				}
				vals = append(vals, vecVal)
			}
			vecln := len(vals)
			if first {
				vec := reflect.MakeSlice(x.Type(), vecln, vecln)
				for i, k := range vals {
					vec.Index(i).Set(k)
				}
				x.Set(vec)
			} else {
				vec := reflect.MakeSlice(valField.Type(), vecln, vecln)
				for i, k := range vals {
					vec.Index(i).Set(k)
				}
				valField.Set(vec)
			}
		}
	case SdpPackDataType_Map:
		{
			ln, err := sdp.unpackNumber()
			if err != nil {
				return err
			}
			var keyType reflect.Type
			var valType reflect.Type
			if first {
				if x.Kind() == reflect.Map && x.CanSet() {
					keyType = x.Type().Key()
					valType = x.Type().Elem()
				}
			} else if valField.Kind() == reflect.Map && valField.CanSet() {
				keyType = valField.Type().Key()
				valType = valField.Type().Elem()
			}

			if keyType == nil {
				for i := 0; i < int(ln); i++ {
					sdp.skipHeadField()
					sdp.skipHeadField()
				}
				break
			}

			valsKey := make([]reflect.Value, 0, ln)
			valsVal := make([]reflect.Value, 0, ln)
			for i := 0; i < int(ln); i++ {
				mapKey := reflect.New(keyType).Elem()
				mapVal := newValByType(valType)
				err := sdp.unpack(mapKey, true)
				if err != nil {
					return err
				}
				valsKey = append(valsKey, mapKey)
				er := sdp.unpack(mapVal, true)
				if er != nil {
					return er
				}
				valsVal = append(valsVal, mapVal)
			}

			if first {
				mp := reflect.MakeMap(x.Type())
				for i, k := range valsKey {
					mp.SetMapIndex(k, valsVal[i])
				}
				x.Set(mp)
			} else {
				mp := reflect.MakeMap(valField.Type())
				for i, k := range valsKey {
					mp.SetMapIndex(k, valsVal[i])
				}
				valField.Set(mp)
			}
		}
	case SdpPackDataType_StructBegin:
		{
			stVal := x
			if !first {
				stVal = valField
			}
			if stVal.Kind() != reflect.Struct {
				sdp.skipToStructEnd()
				return nil
			}
			for {
				err := sdp.unpack(stVal, false)
				if err == errStructEnd {
					break
				}
				if err != nil {
					return err
				}
			}
		}
	case SdpPackDataType_StructEnd:
		{
			return errStructEnd
		}
	default:
		return errInvalidType
	}

	return nil
}

func newValByType(ty reflect.Type) reflect.Value {
	if ty.Kind() == reflect.Map {
		return reflect.New(reflect.MakeMap(ty).Type()).Elem()
	} else if ty.Kind() == reflect.Slice {
		return reflect.New(reflect.MakeSlice(ty, 0, 0).Type()).Elem()
	}
	return reflect.New(ty).Elem()
}

func Encode(data interface{}) []byte {
	sdp := Sdp{}
	sdp.pack(0, data, true, true)
	return sdp.buf
}

func Decode(x interface{}, data []byte) error {
	if reflect.TypeOf(x).Kind() != reflect.Ptr {
		return errNeedPtr
	}
	sdp := Sdp{data, 0}
	return sdp.unpack(reflect.ValueOf(x).Elem(), true)
}

func PackSdpProtocol(data []byte) []byte {
	msglen := len(data) + 4
	sdpMsg := Sdp{}
	sdpMsg.packByte(byte(msglen >> 24))
	sdpMsg.packByte(byte(msglen >> 16))
	sdpMsg.packByte(byte(msglen >> 8))
	sdpMsg.packByte(byte(msglen))
	sdpMsg.packData(data)
	return sdpMsg.buf
}

func SdpLen(b []byte) uint32 {
	_ = b[3] // bounds check hint to compiler; see golang.org/issue/14808
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}
