rule Linux_Exploit_Criscras_fc505c1d
{
	meta:
		author = "Elastic Security"
		id = "fc505c1d-f77d-48cc-b8fe-7b24b9cc6a97"
		fingerprint = "bc5e980599c4c8fc3c9b560738d7187a0c91e2813c64b3ad0ff014230100c8d8"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Criscras"
		reference_sample = "7399f6b8fbd6d6c6fb56ab350c84910fe19cc5da67e4de37065ff3d4648078ab"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux.Exploit.Criscras malware"
		filetype = "executable"

	strings:
		$a = { 0C 89 21 89 E3 31 C0 B0 0B CD 80 31 C0 FE C0 CD }

	condition:
		all of them
}
