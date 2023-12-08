rule EQGRP_BBANJO
{
	meta:
		description = "EQGRP Toolset Firewall - file BBANJO-3011.exe"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "f09c2f90464781a08436321f6549d350ecef3d92b4f25b95518760f5d4c9b2c3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "get_lsl_interfaces" fullword ascii
		$s2 = "encryptFC4Payload" fullword ascii
		$s3 = ".got_loader" fullword ascii
		$s4 = "beacon_getconfig" fullword ascii
		$s5 = "LOADED" fullword ascii
		$s6 = "FormBeaconPacket" fullword ascii
		$s7 = "beacon_reconfigure" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <50KB and all of them )
}
