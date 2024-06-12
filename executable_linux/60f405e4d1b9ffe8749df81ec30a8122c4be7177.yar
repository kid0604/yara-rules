rule Linux_Trojan_Metasploit_2b0ad6f0
{
	meta:
		author = "Elastic Security"
		id = "2b0ad6f0-44d2-4e7e-8cca-2b0ae1b88d48"
		fingerprint = "b15da42f957107d54bfad78eff3a703cc2a54afcef8207d42292f2520690d585"
		creation_date = "2024-05-07"
		last_modified = "2024-05-21"
		description = "Detects x64 msfvenom find TCP port payloads"
		threat_name = "Linux.Trojan.Metasploit"
		reference_sample = "aa2bce61511c72ac03562b5178aad57bce8b46916160689ed07693790cbfbeec"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		filetype = "executable"

	strings:
		$str1 = { 48 31 FF 48 31 DB B3 18 48 29 DC 48 8D 14 24 48 C7 02 10 00 00 00 48 8D 74 24 08 6A 34 58 0F 05 48 FF C7 }
		$str2 = { 48 FF CF 6A 02 5E 6A 21 58 0F 05 48 FF CE 79 }
		$str3 = { 48 89 F3 BB 41 2F 73 68 B8 2F 62 69 6E 48 C1 EB 08 48 C1 E3 20 48 09 D8 50 48 89 E7 48 31 F6 48 89 F2 6A 3B 58 0F 05 }

	condition:
		all of them
}
