rule Malwareusedbycyberthreatactor3
{
	meta:
		description = "Detects malware used by cyber threat actor 3"
		os = "windows"
		filetype = "executable"

	strings:
		$STR1 = { 50 68 80 00 00 00 68 FF FF 00 00 51 C7 44 24 1C 3a 8b 00 00 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
