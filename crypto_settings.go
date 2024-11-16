package crypto_settings

// This function pointer will be used to hand the bitstream for xor decryption
// to the ebpf program.
var EBPFXOrBitstreamRegister func(bitstream []byte) = nil
