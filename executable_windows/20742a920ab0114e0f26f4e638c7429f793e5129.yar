rule NtGodMode
{
	meta:
		description = "Chinese Hacktool Set - file NtGodMode.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8baac735e37523d28fdb6e736d03c67274f7db77"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "to HOST!" fullword ascii
		$s1 = "SS.EXE" fullword ascii
		$s5 = "lstrlen0" fullword ascii
		$s6 = "Virtual" fullword ascii
		$s19 = "RtlUnw" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <45KB and all of them
}
