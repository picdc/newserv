.meta name="EXP share v2"
.meta description="Award EXP to local\nhuman even when NPC\n(spawned via $npc)\ndeals killing blow."

# Reverse-engineered from PSO v2 DC US (2OEF), RAM dump + runtime GDB
# breakpoints on Flycast.
#
# Problem : when an offensive NPC spawned via $npc deals the killing blow
# without the human player having tagged the enemy, no EXP is awarded to
# anyone. The NPC never levels up and the human gets nothing.
#
# Root cause identified at runtime :
#
#   Function 0x8C01288C is the enemy-death EXP distributor. At entry it
#   reads enemy+0x306 (u16 = last human attacker entity id), calls
#   get_player_by_id(id) at 0x8C021EF8, checks the result for null.
#
#   For human kills : enemy+0x306 = human's slot, lookup returns human,
#   distribution proceeds → EXP awarded.
#
#   For NPC-only kills : enemy+0x306 = 0xFFFF (sentinel for "no human
#   attacker"). get_player_by_id(0xFFFF) returns null. The function
#   bails out immediately at 0x8C0128A0 (bt 0x8C012980).
#
# Runtime confirmation: a breakpoint on 0x8C0128A0 fires when ASH (NPC
# spawned via $npc 9) kills an enemy, with r4=0xFFFF and r14=0.
#
# Fix strategy :
#
#   We hook the bail epilogue at 0x8C012980 to redirect to a trampoline
#   placed in an unused zero-filled region of the PSO binary (the padding
#   between two Shift-JIS text tables at 0x8C296BA0-0x8C299673, a
#   ~10KB stable zero region verified across multiple RAM dumps).
#
#   The trampoline inspects r14 :
#     - If r14 != null (the normal bail cases 2, 3, or normal exit) →
#       perform the original epilogue (pop saved regs, rts).
#     - If r14 == null (only the BAIL 1 case) → load r14 with
#       player_array[local_slot] (= local human) and jump back to
#       0x8C0128A2, just past the BAIL 1. The function continues with
#       the human as the EXP recipient.
#
# Globals used :
#   0x8C428D48 : u32 LOCAL_CLIENT_SLOT (0..3, slot of the local human player)
#   0x8C42D92C : TObjPlayer* player_array[4]
#
# Block 1 overwrites the original 12-byte epilogue at 0x8C012980 with a
# jmp to the trampoline. The trampoline itself re-implements the
# epilogue for the normal case and the fix for the BAIL 1 case.
#
# Block 2 installs the trampoline at 0x8C296BA0. Without symbol
# assembly support I hand-encoded the instructions and verified via
# round-trip decode + PC-relative resolution checks.
#
# Only the US version (2OEF) has been analysed so far; other versions
# currently reuse the same addresses as placeholders.

.versions 2OJ4 2OJ5 2OJF 2OEF 2OPF

entry_ptr:
reloc0:
  .data     start
start:
  .include  WriteCodeBlocks

  # Block 1 : overwrite function epilogue at 0x8C012980 (12 bytes)
  #
  # Original :
  #   0x8C012980: 4F26  lds.l @r15+, pr
  #   0x8C012982: 6BF6  mov.l @r15+, r11
  #   0x8C012984: 6CF6  mov.l @r15+, r12
  #   0x8C012986: 6DF6  mov.l @r15+, r13
  #   0x8C012988: 000B  rts
  #   0x8C01298A: 6EF6  mov.l @r15+, r14
  #
  # Replacement :
  #   0x8C012980: D001  mov.l @(pc+4), r0     ; r0 = trampoline addr
  #   0x8C012982: 402B  jmp @r0
  #   0x8C012984: 0009  nop                    ; delay slot
  #   0x8C012986: 0009  nop                    ; padding
  #   0x8C012988: .data 0x8C296BA0
  .align    4
  .data     <VERS 0x8C012980 0x8C012980 0x8C012980 0x8C012980 0x8C012980>
  .data     12
  .binary   01D02B4009000900A06B298C

  # Block 2 : trampoline at 0x8C296BA0 (44 bytes)
  #
  #   0x8C296BA0: 2EE8  tst r14, r14
  #   0x8C296BA2: 8905  bt fix_null            ; → 0x8C296BB0
  #   0x8C296BA4: 4F26  lds.l @r15+, pr        ; original epilogue (r14 != null path)
  #   0x8C296BA6: 6BF6  mov.l @r15+, r11
  #   0x8C296BA8: 6CF6  mov.l @r15+, r12
  #   0x8C296BAA: 6DF6  mov.l @r15+, r13
  #   0x8C296BAC: 000B  rts
  #   0x8C296BAE: 6EF6  mov.l @r15+, r14       ; rts delay slot
  # fix_null:                                   ; (r14 == null = BAIL 1 case)
  #   0x8C296BB0: D003  mov.l @(pc+0xC), r0    ; r0 = &local_slot (0x8C428D48)
  #   0x8C296BB2: 6002  mov.l @r0, r0           ; r0 = local_slot value (0..3)
  #   0x8C296BB4: 4008  shll2 r0                ; r0 = slot * 4
  #   0x8C296BB6: D103  mov.l @(pc+0xC), r1    ; r1 = &player_array (0x8C42D92C)
  #   0x8C296BB8: 0E1E  mov.l @(r0, r1), r14   ; r14 = player_array[local_slot]
  #   0x8C296BBA: D003  mov.l @(pc+0xC), r0    ; r0 = resume address (0x8C0128A2)
  #   0x8C296BBC: 402B  jmp @r0                 ; resume in distributor
  #   0x8C296BBE: 0009  nop                     ; jmp delay slot
  #   0x8C296BC0: .data 0x8C428D48              ; LOCAL_CLIENT_SLOT addr
  #   0x8C296BC4: .data 0x8C42D92C              ; player_array addr
  #   0x8C296BC8: .data 0x8C0128A2              ; resume after BAIL 1
  .align    4
  .data     <VERS 0x8C296BA0 0x8C296BA0 0x8C296BA0 0x8C296BA0 0x8C296BA0>
  .data     44
  .binary   E82E0589264FF66BF66CF66D0B00F66E03D00260084003D11E0E03D02B400900488D428C2CD9428CA228018C

  .align    4
  .data     0x00000000
  .data     0x00000000
