rule Windows_Ransomware_Maze_46f40c40 : beta
{
	meta:
		author = "Elastic Security"
		id = "46f40c40-05a4-4163-a62d-675882149781"
		fingerprint = "efe1e0d23fbfd72fd2843a9c8d5e62394ef8c75b9a7bd03fdbb36e2cf97bf12e"
		creation_date = "2020-04-18"
		last_modified = "2021-10-04"
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
		$b1 = "Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms" wide fullword
		$b2 = "Maze Ransomware" wide fullword
		$b3 = "%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s" wide fullword

	condition:
		2 of ($b*)
}
