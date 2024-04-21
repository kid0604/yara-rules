rule case_15184_K_1_06_13_2022_lnk
{
	meta:
		description = "15184_ - file K-1 06.13.2022.lnk.lnk"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2022-11-28"
		hash1 = "1bf9314ae67ab791932c43e6c64103b1b572a88035447dae781bffd21a1187ad"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword ascii
		$s2 = "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide
		$s3 = "<..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" fullword wide
		$s4 = "-c \"&{'p8ArwZsj8ZO+Zy/dHPeI+siGhbaxtEhzwmd3zVObm9uG2CGKqz5m4AdzKWWzPmKrjJieG4O9';$BxQ='uYnIvc3RhdHMvUkppMnJRSTRRWHJXQ2ZnZG1pLyI" wide
		$s5 = "WindowsPowerShell" fullword wide
		$s6 = "black-dog" fullword ascii
		$s7 = "powershell.exe" fullword wide
		$s8 = "S-1-5-21-1499925678-132529631-3571256938-1001" fullword wide

	condition:
		uint16(0)==0x004c and filesize <10KB and 1 of ($x*) and all of them
}
