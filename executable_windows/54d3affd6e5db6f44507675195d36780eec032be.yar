rule Unspecified_Malware_Jul17_1A
{
	meta:
		description = "Detects samples of an unspecified malware - July 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Winnti HDRoot VT"
		date = "2017-07-07"
		hash1 = "e1c38142b6194237a4cd4603829aa6edb6436e7bba15e3e6b0c9e8c6b629b42b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%SystemRoot%\\System32\\wuauserv.dll" fullword ascii
		$s2 = "systemroot%\\system32\\wuauserv.dll" fullword ascii
		$s3 = "ocgen.logIN" fullword wide
		$s4 = "ocmsn.logIN" fullword wide
		$s5 = "Install.log" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and all of them )
}
