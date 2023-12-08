rule Fireball_winsap
{
	meta:
		description = "Detects Fireball malware - file winsap.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		hash1 = "c7244d139ef9ea431a5b9cc6a2176a6a9908710892c74e215431b99cd5228359"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "aHR0cDovL2" ascii
		$s2 = "%s\\svchost.exe -k %s" fullword wide
		$s3 = "\\SETUP.dll" wide
		$s4 = "WinSAP.dll" fullword ascii
		$s5 = "Error %u in WinHttpQueryDataAvailable." fullword ascii
		$s6 = "UPDATE OVERWRITE" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 4 of them )
}
