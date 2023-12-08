import "pe"

rule DragonFly_APT_Sep17_3
{
	meta:
		description = "Detects malware from DrqgonFly APT report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
		date = "2017-09-12"
		hash1 = "b051a5997267a5d7fa8316005124f3506574807ab2b25b037086e2e971564291"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "kernel64.dll" fullword ascii
		$s2 = "ws2_32.dQH" fullword ascii
		$s3 = "HGFEDCBADCBA" fullword ascii
		$s4 = "AWAVAUATWVSU" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <40KB and (pe.imphash()=="6f03fb864ff388bac8680ac5303584be" or all of them ))
}
