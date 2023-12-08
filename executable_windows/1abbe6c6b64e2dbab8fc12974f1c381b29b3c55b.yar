rule EQGRP_BLIAR_BLIQUER
{
	meta:
		description = "EQGRP Toolset Firewall - from files BLIAR-2110, BLIQUER-2230"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash2 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Do you wish to activate the implant that is already on the firewall? (y/n): " fullword ascii
		$x2 = "There is no implant present on the firewall." fullword ascii
		$x3 = "Implant Version :%lx%lx%lx" fullword ascii
		$x4 = "You may now connect to the implant using the pbd idkey" fullword ascii
		$x5 = "No reply from persistant back door." fullword ascii
		$x6 = "rm -rf pbd.wc; wc -c %s > pbd.wc" fullword ascii
		$p1 = "PBD_GetVersion" fullword ascii
		$p2 = "pbd/pbdEncrypt.bin" fullword ascii
		$p3 = "pbd/pbdGetVersion.pkt" fullword ascii
		$p4 = "pbd/pbdStartWrite.bin" fullword ascii
		$p5 = "pbd/pbd_setNewHookPt.pkt" fullword ascii
		$p6 = "pbd/pbd_Upload_SinglePkt.pkt" fullword ascii
		$s1 = "Unable to fetch hook and jmp addresses for this OS version" fullword ascii
		$s2 = "Could not get hook and jump addresses" fullword ascii
		$s3 = "Enter the name of a clean implant binary (NOT an image):" fullword ascii
		$s4 = "Unable to read dat file for OS version 0x%08lx" fullword ascii
		$s5 = "Invalid implant file" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <3000KB and (1 of ($x*) or 1 of ($p*))) or (3 of them )
}
