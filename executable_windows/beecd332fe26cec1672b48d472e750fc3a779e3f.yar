rule CheshireCat_Gen2
{
	meta:
		description = "Auto-generated rule - from files 32159d2a16397823bc882ddd3cd77ecdbabe0fde934e62f297b8ff4d7b89832a, 63735d555f219765d486b3d253e39bd316bbcb1c0ec595ea45ddf6e419bef3cb"
		author = "Florian Roth"
		reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
		date = "2015-08-08"
		super_rule = 1
		score = 70
		hash1 = "ec41b029c3ff4147b6a5252cb8b659f851f4538d4af0a574f7e16bc1cd14a300"
		hash2 = "32159d2a16397823bc882ddd3cd77ecdbabe0fde934e62f297b8ff4d7b89832a"
		hash3 = "63735d555f219765d486b3d253e39bd316bbcb1c0ec595ea45ddf6e419bef3cb"
		hash4 = "c074aeef97ce81e8c68b7376b124546cabf40e2cd3aff1719d9daa6c3f780532"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Interface\\%s\\info" fullword ascii
		$a2 = "Interface\\%s\\info\\%s" fullword ascii
		$a3 = "CLSID\\%s\\info\\%s" fullword ascii
		$a4 = "CLSID\\%s\\info" fullword ascii
		$b1 = "Windows Shell Icon Handler" fullword wide
		$b2 = "Microsoft Shell Icon Handler" fullword wide
		$s1 = "\\StringFileInfo\\%s\\FileVersion" fullword ascii
		$s2 = "CLSID\\%s\\AuxCLSID" fullword ascii
		$s3 = "lnkfile\\shellex\\IconHandler" fullword ascii
		$s4 = "%s: %s, %.2hu %s %hu %2.2hu:%2.2hu:%2.2hu GMT" fullword ascii
		$s5 = "%sMutex" fullword ascii
		$s6 = "\\ShellIconCache" fullword ascii
		$s7 = "+6Service Pack " fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 7 of ($s*) and 2 of ($a*) and 1 of ($b*)
}
