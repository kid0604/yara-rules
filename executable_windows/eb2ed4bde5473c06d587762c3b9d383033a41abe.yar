rule ProxyTool1
{
	meta:
		description = "Detects the presence of ProxyTool1"
		os = "windows"
		filetype = "executable"

	strings:
		$STR1 = "pmsconfig.msi" wide
		$STR2 = "pmslog.msi" wide

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and any of them
}
