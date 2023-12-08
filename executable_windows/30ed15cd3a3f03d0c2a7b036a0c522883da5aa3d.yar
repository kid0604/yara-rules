rule Backdoor_Redosdru_Jun17 : HIGHVOL
{
	meta:
		description = "Detects malware Redosdru - file systemHome.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/OOB3mH"
		date = "2017-06-04"
		hash1 = "4f49e17b457ef202ab0be905691ef2b2d2b0a086a7caddd1e70dd45e5ed3b309"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%s\\%d.gho" fullword ascii
		$x2 = "%s\\nt%s.dll" fullword ascii
		$x3 = "baijinUPdate" fullword ascii
		$s1 = "RegQueryValueEx(Svchost\\netsvcs)" fullword ascii
		$s2 = "serviceone" fullword ascii
		$s3 = "\x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#f \x1f#" fullword ascii
		$s4 = "servicetwo" fullword ascii
		$s5 = "UpdateCrc" fullword ascii
		$s6 = "\x1f#[ \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#" fullword ascii
		$s7 = "nwsaPAgEnT" fullword ascii
		$s8 = "%-24s %-15s 0x%x(%d) " fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <700KB and 1 of ($x*) or 4 of them )
}
