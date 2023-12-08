rule Stuxnet_Malware_3
{
	meta:
		description = "Stuxnet Sample - file ~WTR4141.tmp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "6bcf88251c876ef00b2f32cf97456a3e306c2a263d487b0a50216c6e3cc07c6a"
		hash2 = "70f8789b03e38d07584f57581363afa848dd5c3a197f2483c6dfa4f3e7f78b9b"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "SHELL32.DLL.ASLR." fullword wide
		$s1 = "~WTR4141.tmp" fullword wide
		$s2 = "~WTR4132.tmp" fullword wide
		$s3 = "totalcmd.exe" fullword wide
		$s4 = "wincmd.exe" fullword wide
		$s5 = "http://www.realtek.com0" fullword ascii
		$s6 = "{%08x-%08x-%08x-%08x}" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <150KB and ($x1 or 3 of ($s*))) or (5 of them )
}
