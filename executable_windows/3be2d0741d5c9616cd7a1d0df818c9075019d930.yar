import "pe"

rule Xtreme_Sep17_2
{
	meta:
		description = "Detects XTREME sample analyzed in September 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-09-27"
		hash1 = "f8413827c52a5b073bdff657d6a277fdbfda29d909b4247982f6973424fa2dcc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Spy24.exe" fullword wide
		$s2 = "Remote Service Application" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <3000KB and all of them )
}
