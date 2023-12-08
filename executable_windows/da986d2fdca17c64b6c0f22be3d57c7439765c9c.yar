rule ProxyTool3
{
	meta:
		description = "Detects the presence of ProxyTool3"
		os = "windows"
		filetype = "executable"

	strings:
		$STR2 = {8A 04 17 8B FB 34 A7 46 88 02 83 C9 FF}

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and $STR2
}
