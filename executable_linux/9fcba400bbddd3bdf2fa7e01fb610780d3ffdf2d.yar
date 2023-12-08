rule EXT_HKTL_MAL_TinyShell_Backdoor_SPARC
{
	meta:
		author = "Mandiant"
		description = "Detects Tiny Shell variant for SPARC - an open-source UNIX backdoor"
		date = "2022-03-17"
		reference = "https://www.mandiant.com/resources/blog/unc2891-overview"
		score = 80
		os = "linux"
		filetype = "executable"

	strings:
		$sb_xor_1 = { DA 0A 80 0C 82 18 40 0D C2 2A 00 0B 96 02 E0 01 98 03 20 01 82 1B 20 04 80 A0 00 01 82 60 20 00 98 0B 00 01 C2 4A 00 0B 80 A0 60 00 32 BF FF F5 C2 0A 00 0B 81 C3 E0 08 }
		$sb_xor_2 = { C6 4A 00 00 80 A0 E0 00 02 40 00 0B C8 0A 00 00 85 38 60 00 C4 09 40 02 84 18 80 04 C4 2A 00 00 82 00 60 01 80 A0 60 04 83 64 60 00 10 6F FF F5 90 02 20 01 81 C3 E0 08 }

	condition:
		uint32(0)==0x464C457F and ( uint16(0x10)&0x0200==0x0200) and ( uint16(0x12)&0x0200==0x0200) and 1 of them
}
