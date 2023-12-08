rule ms10048_x86
{
	meta:
		description = "Chinese Hacktool Set - file ms10048-x86.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e57b453966e4827e2effa4e153f2923e7d058702"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "[ ] Resolving PsLookupProcessByProcessId" fullword ascii
		$s2 = "The target is most likely patched." fullword ascii
		$s3 = "Dojibiron by Ronald Huizer, (c) master@h4cker.us ." fullword ascii
		$s4 = "[ ] Creating evil window" fullword ascii
		$s5 = "%sHANDLEF_INDESTROY" fullword ascii
		$s6 = "[+] Set to %d exploit half succeeded" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 4 of them
}
