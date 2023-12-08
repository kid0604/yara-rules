rule Furtim_Parent_1
{
	meta:
		description = "Detects Furtim Parent Malware"
		author = "Florian Roth"
		reference = "https://sentinelone.com/blogs/sfg-furtims-parent/"
		date = "2016-07-16"
		hash1 = "766e49811c0bb7cce217e72e73a6aa866c15de0ba11d7dda3bd7e9ec33ed6963"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "dqrChZonUF" fullword ascii
		$s1 = "Egistec" fullword wide
		$s2 = "Copyright (C) 2016" fullword wide
		$op1 = { c0 ea 02 88 55 f8 8a d1 80 e2 03 }
		$op2 = { 5d fe 88 55 f9 8a d0 80 e2 0f c0 }
		$op3 = { c4 0c 8a d9 c0 eb 02 80 e1 03 88 5d f8 8a d8 c0 }

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and ($x1 or ( all of ($s*) and all of ($op*)))) or all of them
}
