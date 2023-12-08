import "elf"

rule DarkSide_BM
{
	meta:
		author = "rivitna"
		family = "ransomware.darkside_blackmatter"
		description = "DarkSide/BlackMatter ransomware Windows payload"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$h1 = { 64 A1 30 00 00 00     // mov  eax, large fs:30h
                8B B0 A4 00 00 00     // mov  esi, [eax+0A4h]
                8B B8 A8 00 00 00     // mov  edi, [eax+0A8h]
                83 FE 05              // cmp  esi, 5
                75 05                 // jnz  short L1
                83 FF 01 }

	condition:
		(( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) and ((1 of ($h*)))
}
