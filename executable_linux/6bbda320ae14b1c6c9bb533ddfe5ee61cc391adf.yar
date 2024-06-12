rule Linux_Trojan_Metasploit_ccc99be1
{
	meta:
		author = "Elastic Security"
		id = "ccc99be1-6ea9-4090-acba-3bbe82b127c1"
		fingerprint = "88e30402974b853e5f83a3033129d99e7dd1f6b31b5855b1602ef2659a0f7f56"
		creation_date = "2024-05-07"
		last_modified = "2024-05-21"
		description = "Detects x64 msfvenom pingback bind shell payloads"
		threat_name = "Linux.Trojan.Metasploit"
		reference_sample = "0e9f52d7aa6bff33bfbdba6513d402db3913d4036a5e1c1c83f4ccd5cc8107c8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		filetype = "executable"

	strings:
		$str1 = { 56 50 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 48 85 C0 }
		$str2 = { 51 48 89 E6 54 5E 6A 31 58 6A 10 5A 0F 05 6A 32 58 6A 01 5E 0F 05 }
		$str3 = { 6A 2B 58 99 52 52 54 5E 6A 1C 48 8D 14 24 0F 05 48 97 }
		$str4 = { 5E 48 31 C0 48 FF C0 0F 05 6A 3C 58 6A 01 5F 0F 05 }

	condition:
		all of them
}
