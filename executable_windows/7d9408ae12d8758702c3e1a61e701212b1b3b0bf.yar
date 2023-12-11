rule EQGRP_Implants_Gen1
{
	meta:
		description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, lpexe, writeJetPlow-2130"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
		hash3 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash4 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash5 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash6 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash7 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
		hash8 = "ee3e3487a9582181892e27b4078c5a3cb47bb31fc607634468cc67753f7e61d7"
		hash9 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "WARNING:  Session may not have been closed!" fullword ascii
		$s2 = "EXEC Packet Processed" fullword ascii
		$s3 = "Failed to insert the command into command list." fullword ascii
		$s4 = "Send_Packet: Trying to send too much data." fullword ascii
		$s5 = "payloadLength >= MAX_ALLOW_SIZE." fullword ascii
		$s6 = "Wrong Payload Size" fullword ascii
		$s7 = "Unknown packet received......" fullword ascii
		$s8 = "Returned eax = %08x" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <6000KB and (2 of ($s*))) or (5 of them )
}
