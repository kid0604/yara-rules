rule Mal_http_EXE : Trojan
{
	meta:
		description = "Detects trojan from APT report named http.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		score = 80
		hash1 = "ad191d1d18841f0c5e48a5a1c9072709e2dd6359a6f6d427e0de59cfcd1d9666"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Content-Disposition: form-data; name=\"file1\"; filename=\"%s\"" fullword ascii
		$x2 = "%ALLUSERSPROFILE%\\Accessories\\wordpade.exe" fullword ascii
		$x3 = "\\dumps.dat" fullword ascii
		$x4 = "\\wordpade.exe" fullword ascii
		$x5 = "\\%s|%s|4|%d|%4d-%02d-%02d %02d:%02d:%02d|" fullword ascii
		$x6 = "\\%s|%s|5|%d|%4d-%02d-%02d %02d:%02d:%02d|" fullword ascii
		$x7 = "cKaNBh9fnmXgJcSBxx5nFS+8s7abcQ==" fullword ascii
		$x8 = "cKaNBhFLn1nXMcCR0RlbMQ==" fullword ascii
		$s1 = "SELECT * FROM moz_logins;" fullword ascii
		$s2 = "makescr.dat" fullword ascii
		$s3 = "%s\\Mozilla\\Firefox\\profiles.ini" fullword ascii
		$s4 = "?moz-proxy://" fullword ascii
		$s5 = "[%s-%s] Title: %s" fullword ascii
		$s6 = "Cforeign key mismatch - \"%w\" referencing \"%w\"" fullword ascii
		$s7 = "Windows 95 SR2" fullword ascii
		$s8 = "\\|%s|0|0|" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and (1 of ($x*) and 2 of ($s*))) or (3 of ($x*))
}
