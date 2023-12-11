import "pe"

rule HiddenCobra_FallChill_2
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318A"
		date = "2017-11-15"
		hash1 = "0a118eb23399000d148186b9079fa59caf4c3faa7e7a8f91533e467ac9b6ff41"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s\\%s.dll" fullword wide
		$s2 = "yurdkr.dll" fullword ascii
		$s3 = "c%sd.e%sc %s > \"%s\" 2>&1" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (pe.imphash()=="cb36dcb9909e29a38c387b8a87e7e4ed" or (2 of them ))
}
