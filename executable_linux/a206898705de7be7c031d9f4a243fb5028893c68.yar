rule Linux_Trojan_Mirai_3a85a418
{
	meta:
		author = "Elastic Security"
		id = "3a85a418-2bd9-445a-86cb-657ca7edf566"
		fingerprint = "554aff5770bfe8fdeae94f5f5a0fd7f7786340a95633433d8e686af1c25b8cec"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "86a43b39b157f47ab12e9dc1013b4eec0e1792092d4cef2772a21a9bf4fc518a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Trojan.Mirai variant 3a85a418"
		filetype = "executable"

	strings:
		$a = { 01 D8 66 C1 C8 08 C1 C8 10 66 C1 C8 08 66 83 7C 24 2C FF 89 }

	condition:
		all of them
}
