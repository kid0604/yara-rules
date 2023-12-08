rule PoisonIvy_Sample_6
{
	meta:
		description = "Detects PoisonIvy RAT sample set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash1 = "8c2630ab9b56c00fd748a631098fa4339f46d42b"
		hash2 = "36b4cbc834b2f93a8856ff0e03b7a6897fb59bd3"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "124.133.252.150" fullword ascii
		$x3 = "http://124.133.254.171/up/up.asp?id=%08x&pcname=%s" fullword ascii
		$z1 = "\\temp\\si.txt" ascii
		$z2 = "Daemon Dynamic Link Library" fullword wide
		$z3 = "Microsoft Windows CTF Loader" fullword wide
		$z4 = "\\tappmgmts.dll" ascii
		$z5 = "\\appmgmts.dll" ascii
		$s0 = "%USERPROFILE%\\AppData\\Local\\Temp\\Low\\ctfmon.log" fullword ascii
		$s1 = "%USERPROFILE%\\AppData\\Local\\Temp\\ctfmon.tmp" fullword ascii
		$s2 = "\\temp\\ctfmon.tmp" ascii
		$s3 = "SOFTWARE\\Classes\\http\\shell\\open\\commandV" fullword ascii
		$s4 = "CONNECT %s:%i HTTP/1.0" fullword ascii
		$s5 = "start read histry key" fullword ascii
		$s6 = "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"" fullword ascii
		$s7 = "[password]%s" fullword ascii
		$s8 = "Daemon.dll" fullword ascii
		$s9 = "[username]%s" fullword ascii
		$s10 = "advpack" fullword ascii
		$s11 = "%s%2.2X" fullword ascii
		$s12 = "advAPI32" fullword ascii

	condition:
		( uint16(0)==0x5a4d and 1 of ($x*)) or (8 of ($s*)) or (1 of ($z*) and 3 of ($s*))
}
