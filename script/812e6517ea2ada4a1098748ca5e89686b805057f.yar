rule EQGRP_Implants_Gen4
{
	meta:
		description = "EQGRP Toolset Firewall - from files BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash2 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash3 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash4 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "Command has not yet been coded" fullword ascii
		$s2 = "Beacon Domain  : www.%s.com" fullword ascii
		$s3 = "This command can only be run on a PIX/ASA" fullword ascii
		$s4 = "Warning! Bad or missing Flash values (in section 2 of .dat file)" fullword ascii
		$s5 = "Printing the interface info and security levels. PIX ONLY." fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <3000KB and 3 of them ) or ( all of them )
}
