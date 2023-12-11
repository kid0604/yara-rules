rule Furtim_nativeDLL
{
	meta:
		description = "Detects Furtim malware - file native.dll"
		author = "Florian Roth"
		reference = "MISP 3971"
		date = "2016-06-13"
		hash1 = "4f39d3e70ed1278d5fa83ed9f148ca92383ec662ac34635f7e56cc42eeaee948"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "FqkVpTvBwTrhPFjfFF6ZQRK44hHl26" fullword ascii
		$op0 = { e0 b3 42 00 c7 84 24 ac }
		$op1 = { a1 e0 79 44 00 56 ff 90 10 01 00 00 a1 e0 79 44 }
		$op2 = { bf d0 25 44 00 57 89 4d f0 ff 90 d4 02 00 00 59 }

	condition:
		uint16(0)==0x5a4d and filesize <900KB and $s1 or all of ($op*)
}
