rule Windows_Trojan_Metasploit_a91a6571
{
	meta:
		author = "Elastic Security"
		id = "a91a6571-ae2d-4ab4-878b-38b455f42c01"
		fingerprint = "e372484956eab80e4bf58f4ae1031de705cb52eaefa463aa77af7085c463638d"
		creation_date = "2022-06-08"
		last_modified = "2022-09-29"
		threat_name = "Windows.Trojan.Metasploit"
		reference_sample = "ff7795edff95a45b15b03d698cbdf70c19bc452daf4e2d5e86b2bbac55494472"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Metasploit"
		filetype = "executable"

	strings:
		$a = { FC 48 83 E4 F0 E8 CC 00 00 00 41 51 41 50 52 48 31 D2 51 56 65 48 8B 52 60 48 8B 52 18 48 8B 52 }

	condition:
		all of them
}
