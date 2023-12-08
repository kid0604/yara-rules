rule LightweightBackdoor5
{
	meta:
		description = "Detects a lightweight backdoor based on specific byte patterns"
		os = "windows"
		filetype = "executable"

	strings:
		$strl = { C6 45 F4 74 C6 45 F5 6C C6 45 F6 76 C6 45 F7 63 C6 45 F8 2E C6 45 F9 6E C6 45 FA 6C C6 45 FB 73 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
