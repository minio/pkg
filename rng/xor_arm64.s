// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//+build !noasm
//+build !appengine
//+build !gccgo
//+build !purego

// func xorSliceNEON(in, out []byte, v *[4]uint64)
TEXT ·xorSliceNEON(SB), 7, $0
	MOVD v+48(FP), R2
	MOVD in+0(FP), R0
	MOVD out+24(FP), R1
	MOVD out_len+32(FP), R3
	VLD1 (R2), [V0.B16, V1.B16]
	LSR  $5, R3, R3
	CBZ  R3, done_xor_neon
	CMP  $1, R3
	BEQ  loopback_xor_neon_32

loopback_xor_neon_64:
	SUB  $2, R3, R3
	VLD1 (R0), [V2.B16, V3.B16, V4.B16, V5.B16]
	VEOR V0.B16, V2.B16, V2.B16
	VEOR V1.B16, V3.B16, V3.B16
	VEOR V0.B16, V4.B16, V4.B16
	VEOR V1.B16, V5.B16, V5.B16
	VST1 [V2.B16, V3.B16, V4.B16, V5.B16], (R1)
	ADD  $64, R0
	ADD  $64, R1
	CMP  $1, R3
	BGT  loopback_xor_neon_64
	BEQ  loopback_xor_neon_32
	B    done_xor_neon

loopback_xor_neon_32:
	VLD1 (R0), [V2.B16, V3.B16]
	VEOR V0.B16, V2.B16, V2.B16
	VEOR V1.B16, V3.B16, V3.B16
	VST1 [V2.B16, V3.B16], (R1)

done_xor_neon:
	RET
