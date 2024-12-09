package crypto_settings

import "fmt"

// This function pointer will be used to hand the bitstream for xor decryption
// to the ebpf program.
var EBPFXOrBitstreamRegister func(pn uint64, blockindex uint8, bitstream []byte) = nil
var PotentiallTriggerCryptoGarbageCollector func() = nil
var RegisterFullyReceivedPacket func(pn uint64) = nil

const MAX_BLOCKS_PER_PACKET = 24

func Crypto_debug_println(x ...any) {
	return
	fmt.Println(x...)
}
