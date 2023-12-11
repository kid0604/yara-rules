rule EQGRP_dn_1_0_2_1
{
	meta:
		description = "Detects tool from EQGRP toolset - file dn.1.0.2.1.linux"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "Valid commands are: SMAC, DMAC, INT, PACK, DONE, GO" fullword ascii
		$s2 = "invalid format suggest DMAC=00:00:00:00:00:00" fullword ascii
		$s3 = "SMAC=%02x:%02x:%02x:%02x:%02x:%02x" fullword ascii
		$s4 = "Not everything is set yet" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <30KB and 2 of them )
}
