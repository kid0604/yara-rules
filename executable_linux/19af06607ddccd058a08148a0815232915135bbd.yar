import "pe"

rule MALWARE_Linux_Akira
{
	meta:
		author = "ditekSHen"
		description = "Detects Akira Ransomware Linux"
		os = "linux"
		filetype = "executable"

	strings:
		$x1 = "https://akira" ascii
		$x2 = ":\\akira\\" ascii
		$x3 = ".akira" ascii
		$x4 = "akira_readme.txt" ascii
		$s1 = "--encryption_" ascii
		$s2 = "--share_file" ascii
		$s3 = { 00 24 52 65 63 79 63 6c 65 2e 42 69 6e 00 24 52 45 43 59 43 4c 45 2e 42 49 4e 00 }
		$s4 = " PUBLIC KEY-----" ascii
		$s5 = ".onion" ascii
		$s6 = "/Esxi_Build_Esxi6/./" ascii nocase
		$s7 = "No path to encrypt" ascii
		$s8 = "-fork" fullword ascii

	condition:
		uint16(0)==0x457f and (3 of ($x*) or (1 of ($x*) and 4 of ($s*)) or 6 of ($s*))
}
