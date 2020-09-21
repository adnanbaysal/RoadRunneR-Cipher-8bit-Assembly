/*
 * AFF80_Fast.asm
 *
 *  Created: 15.06.2015 15:54:26
 *   Author: adnanb
 */ 

 ; Key is read from SRAM adress 0x0060-0x0069
.EQU SRAM_KEY  = 0x0060
; Plaintext is located in 0x006A-0x0071 (SRAM)
; Ciphertext is written to the same place after encryption
.EQU SRAM_PTEXT= 0x006A

; Temporary Key is kept at R0-R3
.def K0 = R0
.def K1 = R1
.def K2 = R2
.def K3 = R3


; Block is on R4-R11
.def B0 = R4
.def B1 = R5
.def B2 = R6
.def B3 = R7
.def B4 = R8
.def B5 = R9
.def B6 = R10
.def B7 = R11

; R16-R21 is used for temporary variables -> left state and others
.def T0 = R16
.def T1 = R17
.def T2 = R18
.def T3 = R19
.def T4 = R20
.def T5 = R21; T5 will be zero for ADC

; R24 keeps the round number
.def RN = R22

; S-Box layer Macro
.macro SBOX   
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

.macro M8D
   movw Y,@0
   lsl YL
   adc YL,T5   ;since T5 is 0, this adds carry to lsb, which is necessary to rotate
   eor YL,@0
   lsl YL
   adc YL,T5   ;since T5 is 0, this adds carry to lsb, which is necessary to rotate
   eor @0,YL
   lsl YH
   adc YH,T5   ;since T5 is 0, this adds carry to lsb, which is necessary to rotate
   eor YH,@1
   lsl YH
   adc YH,T5   ;since T5 is 0, this adds carry to lsb, which is necessary to rotate
   eor @1,YH
.endmacro

.macro SM8
   SBOX
   M8D B0,B1
   M8D B2,B3
.endmacro

; load plaintext to registers
   ldi ZH, high(SRAM_PTEXT)
   ldi ZL, low(SRAM_PTEXT)
   ld B0,Z+
   ld B1,Z+
   ld B2,Z+
   ld B3,Z+
   ld B4,Z+
   ld B5,Z+
   ld B6,Z+
   ld B7,Z

; load KEY to registers
   ldi ZH, high(SRAM_KEY)
   ldi ZL, low(SRAM_KEY)
   ld K0,Z+
   ld K1,Z+
   ld K2,Z+
   ld K3,Z+

; Initial whitening
   eor B0,K0
   eor B1,K1
   eor B2,K2
   eor B3,K3

; Initialize round counter
   ldi RN,10

loop: ; round loop

; save left part to temp
   movw T0,B0
   movw T2,B2

   SM8; first S-box and M8 layers
   rcall LOAD_KEY
   eor B0,K0
   eor B1,K1
   eor B2,K2
   eor B3,K3;  round key addition 1*/

   SM8; second S-box and M8 layers
   rcall LOAD_KEY
   eor B0,K0
   eor B1,K1
   eor B2,K2
   eor B3,K3;  round key addition 2*/

   eor B3,RN ; CONSTANT ADDITION MOVED HERE (16.06)

   SM8; third S-box and M8 layers
   rcall LOAD_KEY;  
   eor B0,K0
   eor B1,K1
   eor B2,K2
   eor B3,K3;round key addition 3*/
   
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
   ld K0,Z+
   ld K1,Z+
   ld K2,Z+
   ld K3,Z
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

LOAD_KEY:
   ld K0,Z+
   ld K1,Z+
   cpi ZL,low(SRAM_PTEXT)
   brmi not_last_key1
   ldi ZL,low(SRAM_KEY)
not_last_key1:
   ld K2,Z+
   ld K3,Z+
   cpi ZL,low(SRAM_PTEXT)
   brmi not_last_key2
   ldi ZL,low(SRAM_KEY)
not_last_key2:
   ret
