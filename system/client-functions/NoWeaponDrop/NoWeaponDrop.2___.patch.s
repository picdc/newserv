.meta name="No weapon drop"
.meta description="Disables weapon\ndropping on death\n(freeplay and quest)"
# Reverse-engineered from PSO v2 DC US (2OEF) RAM dump.
# The "player has no-weapon-drop flag" checker is at 0x8C02BBA0 and reads
# player->[0x350] & 0x10000000. It is called from 0x8C023974 during the
# death/drop decision; if it returns 1, the drop code is skipped.
# Patching the checker to always return 1 disables weapon drops entirely.
# Only the US version (2OEF) has been analysed so far; other versions
# currently reuse the same address as a placeholder — they may need
# per-version addresses once traced.

.versions 2OJ4 2OJ5 2OJF 2OEF 2OPF

entry_ptr:
reloc0:
  .offsetof start
start:
  .include  WriteCodeBlocksDC

  .align    4
  .data     <VERS 0x8C02BBA0 0x8C02BBA0 0x8C02BBA0 0x8C02BBA0 0x8C02BBA0>
  .data     4
  rets
  mov       r0, 1

  .align    4
  .data     0x00000000
  .data     0x00000000
