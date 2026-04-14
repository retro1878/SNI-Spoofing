package main

import (
	"encoding/binary"
	"encoding/hex"
	"log"
)

var (
	tlsCHTemplate []byte
	chStatic1     []byte         // TLS record + handshake header + client version
	chStatic2     = []byte{0x20} // Session ID length (32)
	chStatic3     []byte         // Cipher suites, compression, extensions length, SNI type
	chStatic4     []byte         // Extensions between SNI and key_share
	chStatic5     = []byte{0x00, 0x15} // Padding extension type
)

const templateSNI = "mci.ir"

func init() {
	var err error
	tlsCHTemplate, err = hex.DecodeString(
		"1603010200010001fc0303" +
			"41d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b" +
			"20" +
			"bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e210532815" +
			"0024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff" +
			"0100018f" +
			"0000000b00090000066d63692e6972" +
			"000b000403000102000a00160014001d0017001e0019001801000101010201030104" +
			"00230000" +
			"0010000e000c02683208687474702f312e31" +
			"0016000000170000" +
			"000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602" +
			"002b00050403040303" +
			"002d00020101" +
			"003300260024001d0020" +
			"435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217" +
			"001500d5" +
			"000000000000000000000000000000000000000000000000000000000000000000" +
			"000000000000000000000000000000000000000000000000000000000000000000" +
			"000000000000000000000000000000000000000000000000000000000000000000" +
			"000000000000000000000000000000000000000000000000000000000000000000" +
			"000000000000000000000000000000000000000000000000000000000000000000" +
			"000000000000000000000000000000000000000000000000000000000000000000" +
			"000000000000000000000000000000")
	if err != nil {
		log.Fatal("Invalid TLS ClientHello template: ", err)
	}
	if len(tlsCHTemplate) != 517 {
		log.Fatalf("TLS template length mismatch: got %d, want 517", len(tlsCHTemplate))
	}

	sniLen := len(templateSNI)
	chStatic1 = tlsCHTemplate[:11]
	chStatic3 = tlsCHTemplate[76:120]
	chStatic4 = tlsCHTemplate[127+sniLen : 262+sniLen]
}

// buildClientHello constructs a TLS ClientHello with the given random, session ID,
// SNI hostname, and key share. All byte slice arguments must be 32 bytes.
// The result is always 517 bytes with padding adjusted for the SNI length.
func buildClientHello(rnd, sessID, targetSNI, keyShare []byte) []byte {
	sniLen := len(targetSNI)

	// Server Name extension: [ext_data_len][list_len][type=0][name_len][name]
	sniExt := make([]byte, 7+sniLen)
	binary.BigEndian.PutUint16(sniExt[0:2], uint16(sniLen+5))
	binary.BigEndian.PutUint16(sniExt[2:4], uint16(sniLen+3))
	sniExt[4] = 0x00 // host_name type
	binary.BigEndian.PutUint16(sniExt[5:7], uint16(sniLen))
	copy(sniExt[7:], targetSNI)

	// Padding extension: [padding_data_len][zeros...]
	paddingDataLen := 219 - sniLen
	paddingExt := make([]byte, 2+paddingDataLen)
	binary.BigEndian.PutUint16(paddingExt[0:2], uint16(paddingDataLen))

	// Assemble the full ClientHello
	result := make([]byte, 0, 517)
	result = append(result, chStatic1...)
	result = append(result, rnd...)
	result = append(result, chStatic2...)
	result = append(result, sessID...)
	result = append(result, chStatic3...)
	result = append(result, sniExt...)
	result = append(result, chStatic4...)
	result = append(result, keyShare...)
	result = append(result, chStatic5...)
	result = append(result, paddingExt...)
	return result
}
