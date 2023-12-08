rule PoseidonGroup_Malware
{
	meta:
		description = "Detects Poseidon Group Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/73673/poseidon-group-a-targeted-attack-boutique-specializing-in-global-cyber-espionage/"
		date = "2016-02-09"
		modified = "2023-01-27"
		score = 85
		hash1 = "337e94119cfad0b3144af81b72ac3b2688a219ffa0bdf23ca56c7a68fbe0aea4"
		hash2 = "344034c0bf9fcd52883dbc158abf6db687150d40a118d9cd6ebd843e186128d3"
		hash3 = "432b7f7f7bf94260a58ad720f61d91ba3289bf0a9789fc0c2b7ca900788dae61"
		hash4 = "8955df76182005a69f19f5421c355f1868efe65d6b9e0145625dceda94b84a47"
		hash5 = "d090b1d77e91848b1e2f5690b54360bbbd7ef808d017304389b90a0f8423367f"
		hash6 = "d7c8b47a0d0a9181fb993f17e165d75a6be8cf11812d3baf7cf11d085e21d4fb"
		hash7 = "ded0ee29af97496f27d810f6c16d78a3031d8c2193d5d2a87355f3e3ca58f9b3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "c:\\winnt\\system32\\cmd.exe" fullword ascii
		$s2 = "c:\\windows\\system32\\cmd.exe" fullword ascii
		$s3 = "c:\\windows\\command.com" fullword ascii
		$s4 = "copy \"%s\" \"%s\" /Y" fullword ascii
		$s5 = "http://%s/files/" ascii
		$s6 = "\"%s\". %s: \"%s\"." fullword ascii
		$s7 = "0x0666" fullword ascii
		$s8 = "----------------This_is_a_boundary$" fullword ascii
		$s9 = "Server 2012" fullword ascii
		$s10 = "Server 2008" fullword ascii
		$s11 = "Server 2003" fullword ascii
		$a1 = "net.exe group \"Domain Admins\" /domain" fullword ascii
		$a2 = "net.exe group \"Admins. do Dom" fullword ascii
		$a3 = "(SVRID=%d)" fullword ascii
		$a4 = "(TG=%d)" fullword ascii
		$a5 = "(SVR=%s)" fullword ascii
		$a6 = "Set-Cookie:\\b*{.+?}\\n" fullword wide
		$a7 = "net.exe localgroup Administradores" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <650KB and 6 of ($s*)) or (4 of ($s*) and 1 of ($a*))
}
