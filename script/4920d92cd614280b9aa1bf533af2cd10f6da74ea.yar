rule EQGRP_Extrabacon_Output
{
	meta:
		description = "EQGRP Toolset Firewall - Extrabacon exploit output"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "|###[ SNMPresponse ]###" fullword ascii
		$s2 = "[+] generating exploit for exec mode pass-disable" fullword ascii
		$s3 = "[+] building payload for mode pass-disable" fullword ascii
		$s4 = "[+] Executing:  extrabacon" fullword ascii
		$s5 = "appended AAAADMINAUTH_ENABLE payload" fullword ascii

	condition:
		2 of them
}
