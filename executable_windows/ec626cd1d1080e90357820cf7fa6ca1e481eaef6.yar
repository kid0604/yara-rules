import "pe"

rule Foudre_Backdoor_1
{
	meta:
		description = "Detects Foudre Backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/Nbqbt6"
		date = "2017-08-01"
		hash1 = "7e73a727dc8f3c48e58468c3fd0a193a027d085f25fa274a6e187cf503f01f74"
		hash2 = "7ce2c5111e3560aa6036f98b48ceafe83aa1ac3d3b33392835316c859970f8bc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "initialization failed: Reinstall the program" fullword wide
		$s2 = "SnailDriver V1" fullword wide
		$s3 = "lp.ini" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 2 of them )
}
