rule Windows_Trojan_Guloader_c4d9dd33
{
	meta:
		author = "Elastic Security"
		id = "c4d9dd33-b7e7-4ff4-a2f3-62316d064f5a"
		fingerprint = "53a2d6f895cdd1a6384a55756711d9d758b3b20dd0b87d62a89111fd1a20d1d6"
		creation_date = "2021-08-17"
		last_modified = "2021-10-04"
		threat_name = "Windows.Trojan.Guloader"
		reference_sample = "a3e2d5013b80cd2346e37460753eca4a4fec3a7941586cc26e049a463277562e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Guloader"
		filetype = "executable"

	strings:
		$a1 = "This program cannot be run under virtual environment or debugging software !" ascii fullword

	condition:
		all of them
}
