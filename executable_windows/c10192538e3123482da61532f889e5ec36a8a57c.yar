rule update_PcInit
{
	meta:
		description = "Chinese Hacktool Set - file PcInit.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a6facc4453f8cd81b8c18b3b3004fa4d8e2f5344"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\svchost.exe" fullword ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Global\\ps%08x" fullword ascii
		$s4 = "drivers\\" fullword ascii
		$s5 = "StrStrA" fullword ascii
		$s6 = "StrToIntA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <50KB and all of them
}
