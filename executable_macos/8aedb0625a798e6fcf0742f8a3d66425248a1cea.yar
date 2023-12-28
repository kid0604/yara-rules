rule malware_unknown_machOdownloader
{
	meta:
		description = "Mach-O malware"
		author = "JPCERT/CC Incident Response Group"
		hash = "3266e99f14079b55e428193d5b23aa60862fe784ac8b767c5a1d49dfe80afeeb "
		os = "macos"
		filetype = "executable"

	strings:
		$str1 = "DiagPeersHelper" ascii
		$str2 = "DiagnosticsPeer" ascii
		$str3 = "ticsPeer/" ascii
		$func0 = { 48 B9 3F 72 65 73 70 6F 6E 73 }
		$func1 = { 48 B8 74 61 72 20 7A 78 76 66 }
		$func2 = { E8 [4] C7 84 05 [4] 27 20 2D 43 C7 84 05 [4] 43 20 27 00 48 89 DF 4C 89 E6 E8 33 04 00 00 }

	condition:
		( uint32(0)==0xfeedface or uint32(0)==0xcefaedfe or uint32(0)==0xfeedfacf or uint32(0)==0xcffaedfe or uint32(0)==0xcafebabe or uint32(0)==0xbebafeca or uint32(0)==0xcafebabf or uint32(0)==0xbfbafeca) and ( filesize <10MB) and ((2 of ($str*)) or (2 of ($func*)))
}
