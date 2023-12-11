rule ProxyTool2
{
	meta:
		description = "Detects the presence of ProxyTool2 based on specific byte sequences"
		os = "windows"
		filetype = "executable"

	strings:
		$STR1 = { 82 F4 DE D4 D3 C2 CA F5 C8 C8 D3 82 FB F4 DE D4 D3 C2 CA 94 95 FB D4 D1 C4 CF C8 D4 D3 89 C2 DF C2 87 8A CC 87 00 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
