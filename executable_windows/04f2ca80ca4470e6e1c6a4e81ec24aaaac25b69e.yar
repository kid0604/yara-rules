import "pe"

rule henry217
{
	meta:
		description = "Detect the risk of Ransomware henry217 Rule 1"
		hash1 = "8dd3fba314bdef96075961d8e0ee3a45d5a3030f89408d2b7f9d9fa5eedc66cd"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "RansomeWare" ascii
		$s2 = "AESEncrypt" fullword ascii
		$s3 = {AE 5F 6F 8F C5 96 D1 9E}
		$s4 = {59 00 6F 00 75 00 72 00 20 00 66 00 69 00 6C 00 65 00}
		$s5 = {48 00 65 00 6C 00 6C 00 6F}
		$o1 = {68 00 65 00 6E 00 72 00 79 00 32 00 31 00 37}
		$o2 = {43 00 3A 00 5C 00 00 00 2E 00 73 00 79 00 73 00}
		$pdb = {44 3A 5C D4 B4 C2 EB 5C [2-60] 2E 70 64 62}
		$x1 = "RansomeWare.Form1.resources"
		$x2 = "76a60872-fdf3-466a-9d80-a853c3485b32" nocase ascii wide

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and (( all of ($s*) or 1 of ($o*)) or (1 of ($s*) and $pdb) or 1 of ($x*)) and pe.imphash()=="f34d5f2d4577ed6d9ceec516c1f5a744"
}
