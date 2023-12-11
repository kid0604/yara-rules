rule Windows_Shellcode_Generic_29dcbf7a
{
	meta:
		author = "Elastic Security"
		id = "29dcbf7a-2d3b-4e05-a2be-15623bf62d06"
		fingerprint = "e4664ec7bf7dab3fff873fe4b059e97d2defe3b50e540b96dd98481638dcdcd8"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Shellcode.Generic"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects generic Windows shellcode"
		filetype = "executable"

	strings:
		$a1 = { FC 48 83 E4 F0 41 57 41 56 41 55 41 54 55 53 56 57 48 83 EC 40 48 83 EC 40 48 83 EC 40 48 89 E3 }

	condition:
		all of them
}
