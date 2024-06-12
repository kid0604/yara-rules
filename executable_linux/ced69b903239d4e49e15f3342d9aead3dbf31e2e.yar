rule Linux_Trojan_Metasploit_69e20012
{
	meta:
		author = "Elastic Security"
		id = "69e20012-4f5d-42ce-9913-8bf793d2a695"
		fingerprint = "263efec478e54c025ed35bba18a0678ceba36c90f42ccca825f2ba1202e58248"
		creation_date = "2024-05-03"
		last_modified = "2024-05-21"
		threat_name = "Linux.Trojan.Metasploit"
		reference_sample = "debb5d12c1b876f47a0057aad19b897c21f17de7b02c0e42f4cce478970f0120"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Metasploit"
		filetype = "executable"

	strings:
		$mmap = { 31 FF 6A 09 58 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A 6A 07 5A 0F 05 48 85 C0 78 }
		$socket = { 41 59 50 6A 29 58 99 6A 02 5F 6A 01 5E [0-6] 0F 05 48 85 C0 78 }
		$connect = { 51 48 89 E6 6A 10 5A 6A 2A 58 0F 05 59 48 85 C0 79 }
		$failure_handler = { 57 6A 23 58 6A 00 6A 05 48 89 E7 48 31 F6 0F 05 59 59 5F 48 85 C0 79 }
		$exit = { 6A 3C 58 6A 01 5F 0F 05 }
		$receive = { 5A 0F 05 48 85 C0 78 }

	condition:
		all of them
}
