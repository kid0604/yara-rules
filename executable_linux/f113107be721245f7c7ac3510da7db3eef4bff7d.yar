rule Linux_Trojan_Metasploit_1a98f2e2
{
	meta:
		author = "Elastic Security"
		id = "1a98f2e2-9354-4d04-b1c0-d3998e54e2c4"
		fingerprint = "b9865aad13b4d837e7541fe6a501405aa7d694c8fefd96633c0239031ebec17a"
		creation_date = "2024-05-07"
		last_modified = "2024-05-21"
		description = "Detects x86 msfvenom nonx TCP bind shells"
		threat_name = "Linux.Trojan.Metasploit"
		reference_sample = "89be4507c9c24c4ec9a7282f197a9a6819e696d2832df81f7e544095d048fc22"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		filetype = "executable"

	strings:
		$str1 = { 31 DB 53 43 53 6A 02 6A 66 58 99 89 E1 CD 80 96 43 52 }
		$str2 = { 66 53 89 E1 6A 66 58 50 51 56 89 E1 CD 80 B0 66 D1 E3 CD 80 52 52 56 43 89 E1 B0 66 CD 80 93 B6 0C B0 03 CD 80 89 DF }

	condition:
		all of them
}
