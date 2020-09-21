/*
 * AFF80_Small.asm
 *
 *  Created: 15.06.2015 15:42:57
 *   Author: adnanb
 */ 

  ; Key is read from SRAM adress 0x0060-0x0069
.EQU SRAM_KEY  = 0x0060
; Plaintext is located in 0x006A-0x0071 (SRAM). It should start at the location where 
; key bytes finish. Ciphertext is written to the same place after encryption
.EQU SRAM_PTEXT= 0x006A

; Block
.def B0 = R0
.def B1 = R1
.def B2 = R2
.def B3 = R3
.def B4 = R4
.def B5 = R5
.def B6 = R6
.def B7 = R7

; Key
.def K0 = R8
.def K1 = R9
.def K2 = R10
.def K3 = R11

;temporary variables -> left state and others
.def T0 = R16
.def T1 = R17
.def T2 = R18
.def T3 = R19
.def T4 = R20
.def T5 = R21
.def T6 = R22; needed in ADd with Carry

; round counter
.def RN = R23

;MACROS
.macro ADD_KEY ; Smaller area with this macro instead of function
   eor B0,K0
   eor B1,K1
   eor B2,K2
   eor B3,K3
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

; load whitening KEY to registers
   ldi ZH, high(SRAM_KEY)
   ldi ZL, low(SRAM_KEY)
   rcall LOAD_KEY

; Initial whitening
   eor B0,K0
   eor B1,K1
   eor B2,K2
   eor B3,K3

; Initialize round counter and key part counter
   ldi RN,10

loop: ; round loop
; save left part to temp
   movw T0,B0
   movw T2,B2

   rcall SM8K
   rcall SM8K
   eor B3,RN
   rcall SM8K
   rcall SBOX

; Feistel xor, costant xor, and swap
   eor B0,B4
   eor B1,B5
   eor B2,B6
   eor B3,B7
   movw B4,T0
   movw B6,T2

; update round number
   dec RN

; check round number
   cpi RN,0
   breq FINISH
   rjmp loop

FINISH :
; Final whitening
   rcall LOAD_KEY
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

SBOX:; S-Box layer Subroutine
   mov T4,B0
   and B0,B1
   eor B0,B2
   or  B2,B1
   eor B2,B3
   and B3,B0
   eor B3,T4
   and T4,B2
   eor B1,T4
   ret

M8D: ; Using movw in M8 and calling SM8, code size increaseb by 1 instruction (2B)
   movw T4,Y; So total size is 208B but Cyc reduced to 4107 (%16 speed increase)
   lsl T4
   adc T4,T6   ; since T6 is 0, this adds carry to lsb, which is necessary to rotate
   eor T4,YL
   lsl T4
   adc T4,T6   ; since T6 is 0, this adds carry to lsb, which is necessary to rotate
   lsl T5
   adc T5,T6   ; since T6 is 0, this adds carry to lsb, which is necessary to rotate
   eor T5,YH
   lsl T5
   adc T5,T6   ; since T6 is 0, this adds carry to lsb, which is necessary to rotate
   ret

SM8D:
   rcall SBOX
   movw Y,B0
   rcall M8D
   eor B0,T4
   eor B1,T5
   movw Y,B2
   rcall M8D
   eor B2,T4
   eor B3,T5
   ret

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

SM8K:
   rcall SM8D
   rcall LOAD_KEY
   ADD_KEY  
   ret
