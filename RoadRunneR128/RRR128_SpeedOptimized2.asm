/*
 * AFF_Standard.asm
 * Cycle count optimized is standard
 *
 *  Created: 14.06.2015 07:17:08
 *   Author: adnan
 */ 

; Key is read from SRAM adress 0x0060-0x006F
.EQU SRAM_KEY  = 0x0060
; Plaintext is located in 0x0070-0x0077 (SRAM)
; Ciphertext is written to the same place after encryption
.EQU SRAM_PTEXT= 0x0070

; Key is kept at R0-R15
.def K0 = R0
.def K1 = R1
.def K2 = R2
.def K3 = R3
.def K4 = R4
.def K5 = R5
.def K6 = R6
.def K7 = R7
.def K8 = R8
.def K9 = R9
.def K10 = R10
.def K11 = R11
.def K12 = R12
.def K13 = R13
.def K14 = R14
.def K15 = R15

; Block is on R16-R23
.def B0 = R16
.def B1 = R17
.def B2 = R18
.def B3 = R19
.def B4 = R20
.def B5 = R21
.def B6 = R22
.def B7 = R23

; R24-R27 is used for temporary variables -> left state and others
.def T0 = R24
.def T1 = R25
.def T2 = R26
.def T3 = R27
.def T4 = R28

; R29 keeps the round number
.def RN = R29

.macro SBOX;new sbox
   mov T4,B0
   and B0,B1
   eor B0,B2
   or  B2,B1
   eor B2,B3
   and B3,B0
   eor B3,T4
   and T4,B2
   eor B1,T4
.endmacro

.macro M8D//NEW MATRIX : x + x<<<1 + x<<<2
   movw Z,@0
   lsl ZL
   adc ZL,T4   ;since T4 is 0, this adds carry to lsb, which is necessary to rotate
   eor ZL,@0
   lsl ZL
   adc ZL,T4   ;since T4 is 0, this adds carry to lsb, which is necessary to rotate
   eor @0,ZL
   lsl ZH
   adc ZH,T4   ;since T4 is 0, this adds carry to lsb, which is necessary to rotate
   eor ZH,@1
   lsl ZH
   adc ZH,T4   ;since T4 is 0, this adds carry to lsb, which is necessary to rotate
   eor @1,ZH
.endmacro

.macro SM8
   SBOX
   //ldi ZH,0   ;need a zero register to use adc, but ZH is already 0, so no need
   ldi T4,0
   M8D B0,B1
   M8D B2,B3
.endmacro

.macro LOAD_KEY
   ld K0,Z+
   ld K1,Z+
   ld K2,Z+
   ld K3,Z+
.endmacro

.macro ADD_KEY
   eor B0,K0
   eor B1,K1
   eor B2,K2
   eor B3,K3
.endmacro

; load KEY to registers
   ldi ZH, high(SRAM_KEY)
   ldi ZL, low(SRAM_KEY)
   LOAD_KEY
   
; load plaintext to registers
   ld B0,Z+
   ld B1,Z+
   ld B2,Z+
   ld B3,Z+
   ld B4,Z+
   ld B5,Z+
   ld B6,Z+
   ld B7,Z

; Initial whitening
   ADD_KEY

; Initialize round counter
   ldi RN,12

loop: ; round loop

; save left part to temp
   movw T0,B0
   movw T2,B2

   SM8; first S-box and M8 layers
   LOAD_KEY
   ADD_KEY
   cpi ZL,low(SRAM_PTEXT)
   brmi not_last_key
   ldi ZL,low(SRAM_KEY)
not_last_key:   
   SM8; second S-box and M8 layers
   LOAD_KEY
   ADD_KEY
   cpi ZL,low(SRAM_PTEXT)
   brmi not_last_key2
   ldi ZL,low(SRAM_KEY)
not_last_key2:
   ;CONSTANT ADDITION
   eor B3,RN
   SM8; third S-box and M8 layers
   LOAD_KEY
   ADD_KEY
   cpi ZL,low(SRAM_PTEXT)
   brmi not_last_key3
   ldi ZL,low(SRAM_KEY)
not_last_key3:
   SBOX

; Feistel xor, constant xor, and swap
   eor B0,B4
   eor B1,B5
   eor B2,B6
   eor B3,B7
   movw B4,T0
   movw B6,T2

; update round number
   DEC RN

; check round number
   cpi RN,0
   BREQ FINISH
   RJMP loop

FINISH :
; Final whitening
   LOAD_KEY
   eor B4,K0
   eor B5,K1
   eor B6,K2
   eor B7,K3

; Store ciphertext back
   ldi ZH, high(SRAM_PTEXT)
   ldi ZL, low(SRAM_PTEXT)
   st Z+,B4
   st Z+,B5
   st Z+,B6
   st Z+,B7
   st Z+,B0
   st Z+,B1
   st Z+,B2
   st Z,B3
   nop

