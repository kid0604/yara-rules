rule PROMETHIUM_NEODYMIUM_Malware_3
{
	meta:
		description = "Detects PROMETHIUM and NEODYMIUM malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8abDE6"
		date = "2016-12-14"
		hash1 = "2f98ac11c78ad1b4c5c5c10a88857baf7af43acb9162e8077709db9d563bcf02"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s SslHandshakeDone(%d) %d. Secure connection with %s, cipher %s, %d secret bits (%d total), session reused=%s" fullword ascii
		$s2 = "mvhost32.dll" fullword ascii
		$s3 = "sdwin32.dll" fullword ascii
		$s4 = "ofx64.dll" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 2 of them ) or ( all of them )
}
