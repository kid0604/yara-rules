rule Windows_Ransomware_Maze_20caee5b : beta
{
	meta:
		author = "Elastic Security"
		id = "20caee5b-cf7f-4db7-8c3b-67baf63bfc32"
		fingerprint = "47525839e0800f6edec6ad4580682a336e36f7d13bd9e7214eca0f16941016b8"
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
		$a1 = "Win32_ShadowCopy.id='%s'" wide fullword
		$a2 = "\"%s\" shadowcopy delete" wide fullword
		$a3 = "%spagefile.sys" wide fullword
		$a4 = "%sswapfile.sys" wide fullword
		$a5 = "Global\\%s" wide fullword
		$a6 = "DECRYPT-FILES.txt" wide fullword
		$a7 = "process call create \"cmd /c start %s\"" wide fullword

	condition:
		4 of ($a*)
}
