// Copyright (c) 2015-2021 MinIO, Inc.
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

// func xorSlice(rand, out []byte)
TEXT ·xorSlice(SB), 7, $0
	MOVQ  rand+0(FP), SI   // SI: &rand
	MOVQ  out+24(FP), DX   // DX: &out
	MOVQ  out+32(FP), R9   // R9: len(out)
	MOVOU (SI), X0         // in[x]
	SHRQ  $6, R9           // len(in) / 64
	CMPQ  R9, $0
	JEQ   done_xor_sse2_64

loopback_xor_sse2_64:
	MOVOU (DX), X1             // out[x]
	MOVOU 16(DX), X3           // out[x]
	MOVOU 32(DX), X5           // out[x]
	MOVOU 48(DX), X7           // out[x]
	PXOR  X0, X1
	PXOR  X0, X3
	PXOR  X0, X5
	PXOR  X0, X7
	MOVOU X1, (DX)
	MOVOU X3, 16(DX)
	MOVOU X5, 32(DX)
	MOVOU X7, 48(DX)
	ADDQ  $64, DX              // out+=64
	SUBQ  $1, R9
	JNZ   loopback_xor_sse2_64

done_xor_sse2_64:
	RET
