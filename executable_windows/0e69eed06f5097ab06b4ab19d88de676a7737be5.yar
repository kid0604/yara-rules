rule Windows_Ransomware_Maze_61254061 : beta
{
	meta:
		author = "Elastic Security"
		id = "61254061-e8af-47ab-9cce-96debd99a80a"
		fingerprint = "670d9abbdea153ca66f24ef6806f97e9af3efb73f621167e95606da285627d1b"
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
		$c1 = { FC 8B 55 08 8B 44 8A 10 C1 E0 09 8B 4D FC 8B 55 08 8B 4C 8A 10 C1 }
		$c2 = { 72 F0 0C 66 0F 72 D4 14 66 0F EB C4 66 0F 70 E0 39 66 0F FE E6 66 0F 70 }

	condition:
		1 of ($c*)
}
