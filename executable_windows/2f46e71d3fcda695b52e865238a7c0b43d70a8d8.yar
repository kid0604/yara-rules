rule Windows_Trojan_RedLineStealer_63e7e006
{
	meta:
		author = "Elastic Security"
		id = "63e7e006-6c0c-47d8-8090-a6b36f01f3a3"
		fingerprint = "47c7b9a39a5e0a41f26fdf328231eb173a51adfc00948c68332ce72bc442e19e"
		creation_date = "2023-05-01"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "e062c99dc9f3fa780ea9c6249fa4ef96bbe17fd1df38dbe11c664a10a92deece"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan RedLineStealer"
		filetype = "executable"

	strings:
		$a1 = { 30 68 44 27 25 5B 3D 79 21 54 3A }
		$a2 = { 40 5E 30 33 5D 44 34 4A 5D 48 33 }
		$a3 = { 4B EF 4D FF 44 DD 41 70 44 DC 41 00 44 DC 41 03 43 D9 3E 00 44 }

	condition:
		all of them
}
