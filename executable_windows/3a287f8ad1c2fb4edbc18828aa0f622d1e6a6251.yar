rule Dos_sys
{
	meta:
		description = "Chinese Hacktool Set - file sys.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b5837047443f8bc62284a0045982aaae8bab6f18"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "'SeDebugPrivilegeOpen " fullword ascii
		$s6 = "Author: Cyg07*2" fullword ascii
		$s12 = "from golds7n[LAG]'J" fullword ascii
		$s14 = "DAMAGE" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <150KB and all of them
}
