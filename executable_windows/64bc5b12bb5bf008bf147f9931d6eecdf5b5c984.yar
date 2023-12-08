rule Windows_Ransomware_Maze_f88f136f : beta
{
	meta:
		author = "Elastic Security"
		id = "f88f136f-755c-46d6-9dbe-243342ae315a"
		fingerprint = "3fa065d28d864868e49b394e895207c8be2252a9e211ac4bacce10d9ff04607e"
		creation_date = "2020-04-18"
		last_modified = "2021-08-23"
		description = "Identifies MAZE ransomware"
		threat_name = "Windows.Ransomware.Maze"
		reference = "https://www.bleepingcomputer.com/news/security/it-services-giant-cognizant-suffers-maze-ransomware-cyber-attack/"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$d1 = { 00 67 00 20 00 69 00 6E 00 73 00 74 00 72 00 75 00 63 00 74 00 69 00 6F 00 6E 00 73 00 20 00 69 00 6E 00 20 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2D 00 46 00 49 00 4C 00 45 00 53 00 2E }
		$d2 = { 70 C7 8B 75 6D 97 7E FC 19 2A 39 8C A4 AE AD 9C 62 05 B7 68 47 7D 02 F7 D3 0A DA 20 82 AE A8 E7 B2 26 E1 A0 5B 4E 17 09 A6 94 74 CA B6 0B 88 B0 5F 6E 11 E3 B0 EA 2F 40 D7 A2 AB 59 52 E0 F2 C2 19 24 14 95 01 7F CA }
		$d3 = { 77 B3 50 3C B1 9B 5D D4 87 F5 17 DB E1 C7 42 D8 53 24 C2 E2 6A A8 9B 1E FB E5 48 EB 10 48 44 28 64 F8 B6 A1 41 44 D0 42 FA 85 6F 17 57 09 C4 66 93 D2 21 C5 19 71 3A A1 C5 68 2E 67 B1 02 DC D1 }

	condition:
		1 of ($d*)
}
