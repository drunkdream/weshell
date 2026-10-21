package main

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const objRefSignature uint32 = 0x574f454d // "MEOW"

type towerProtocol uint16

const (
	epmProtocolTCP       towerProtocol = 0x07
	epmProtocolNamedPipe towerProtocol = 0x10
)

type stringBinding struct {
	TowerID        towerProtocol
	NetworkAddress string
}

func (s *stringBinding) bytes() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(s.TowerID))
	writeUTF16LE(&b, s.NetworkAddress)
	b.Write([]byte{0, 0})
	b.Write([]byte{0, 0})
	return b.Bytes()
}

type securityBinding struct {
	AuthnSvc      uint16
	AuthzSvc      uint16
	PrincipalName string
}

func (s *securityBinding) bytes() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, s.AuthnSvc)
	binary.Write(&b, binary.LittleEndian, s.AuthzSvc)
	if s.PrincipalName != "" {
		writeUTF16LE(&b, s.PrincipalName)
	}
	b.Write([]byte{0, 0})
	b.Write([]byte{0, 0})
	return b.Bytes()
}

type dualStringArray struct {
	StringBinding   *stringBinding
	SecurityBinding *securityBinding
}

func (d *dualStringArray) save() []byte {
	sb := d.StringBinding.bytes()
	sec := d.SecurityBinding.bytes()
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16((len(sb)+len(sec))/2))
	binary.Write(&b, binary.LittleEndian, uint16(len(sb)/2))
	b.Write(sb)
	b.Write(sec)
	return b.Bytes()
}

type standard struct {
	Flags           uint32
	PublicRefs      uint32
	OXID            uint64
	OID             uint64
	IPID            [16]byte
	DualStringArray *dualStringArray
}

func (s *standard) save() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, s.Flags)
	binary.Write(&b, binary.LittleEndian, s.PublicRefs)
	binary.Write(&b, binary.LittleEndian, s.OXID)
	binary.Write(&b, binary.LittleEndian, s.OID)
	b.Write(s.IPID[:])
	b.Write(s.DualStringArray.save())
	return b.Bytes()
}

type objRef struct {
	Guid           [16]byte
	StandardObjRef *standard
}

func (o *objRef) getBytes() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, objRefSignature)
	binary.Write(&b, binary.LittleEndian, uint32(1)) // STANDARD
	b.Write(o.Guid[:])
	b.Write(o.StandardObjRef.save())
	return b.Bytes()
}

func writeUTF16LE(b *bytes.Buffer, s string) {
	for _, r := range s {
		binary.Write(b, binary.LittleEndian, uint16(r))
	}
}

func parseObjRef(data []byte) (*objRef, error) {
	if len(data) < 24 {
		return nil, errors.New("objref too short")
	}
	if binary.LittleEndian.Uint32(data[0:4]) != objRefSignature {
		return nil, errors.New("bad OBJREF signature")
	}
	flags := binary.LittleEndian.Uint32(data[4:8])
	guid := [16]byte{}
	copy(guid[:], data[8:24])
	o := &objRef{Guid: guid}
	if flags&1 == 0 {
		return o, nil
	}
	o.StandardObjRef = parseStandard(data[24:])
	return o, nil
}

func parseStandard(data []byte) *standard {
	s := &standard{}
	off := 0
	s.Flags = binary.LittleEndian.Uint32(data[off:])
	off += 4
	s.PublicRefs = binary.LittleEndian.Uint32(data[off:])
	off += 4
	s.OXID = binary.LittleEndian.Uint64(data[off:])
	off += 8
	s.OID = binary.LittleEndian.Uint64(data[off:])
	off += 8
	copy(s.IPID[:], data[off:off+16])
	return s
}

func buildObjRef(iid [16]byte, oxid, oid uint64, ipid [16]byte, tower towerProtocol, addr string) []byte {
	sb := &securityBinding{AuthnSvc: 0xa, AuthzSvc: 0xffff}
	stb := &stringBinding{TowerID: tower, NetworkAddress: addr}
	dsa := &dualStringArray{StringBinding: stb, SecurityBinding: sb}
	std := &standard{Flags: 0, PublicRefs: 1, OXID: oxid, OID: oid, IPID: ipid, DualStringArray: dsa}
	return (&objRef{Guid: iid, StandardObjRef: std}).getBytes()
}
