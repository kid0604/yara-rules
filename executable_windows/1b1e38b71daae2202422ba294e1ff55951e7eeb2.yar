rule Malwareusedbycyberthreatactor2
{
	meta:
		description = "Detects potential malware used by cyber threat actor 2"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "_quit"
		$str2 = "_exe"
		$str3 = "_put"
		$str4 = "_got"
		$str5 = "_get"
		$str6 = "_del"
		$str7 = "_dir"
		$str8 = { C7 44 24 18 1F F7}

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
