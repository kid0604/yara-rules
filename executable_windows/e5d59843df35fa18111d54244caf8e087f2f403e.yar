rule EQGRP_Implants_Gen2
{
	meta:
		description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, writeJetPlow-2130"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash6 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Modules persistence file written successfully" fullword ascii
		$x2 = "Modules persistence data successfully removed" fullword ascii
		$x3 = "No Modules are active on the firewall, nothing to persist" fullword ascii
		$s1 = "--cmd %x --idkey %s --sport %i --dport %i --lp %s --implant %s --bsize %hu --logdir %s " fullword ascii
		$s2 = "Error while attemping to persist modules:" fullword ascii
		$s3 = "Error while reading interface info from PIX" fullword ascii
		$s4 = "LP.c:pixFree - Failed to get response" fullword ascii
		$s5 = "WARNING: LP Timeout specified (%lu seconds) less than default (%u seconds).  Setting default" fullword ascii
		$s6 = "Unable to fetch config address for this OS version" fullword ascii
		$s7 = "LP.c: interface information not available for this session" fullword ascii
		$s8 = "[%s:%s:%d] ERROR: " fullword ascii
		$s9 = "extract_fgbg" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <3000KB and 1 of ($x*)) or (5 of them )
}
