rule EQGRP_BUSURPER_3001_724
{
	meta:
		description = "EQGRP Toolset Firewall - file BUSURPER-3001-724.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "6b558a6b8bf3735a869365256f9f2ad2ed75ccaa0eefdc61d6274df4705e978b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "IMPLANT" fullword ascii
		$s2 = "KEEPGOING" fullword ascii
		$s3 = "upgrade_implant" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <200KB and 2 of them ) or ( all of them )
}
