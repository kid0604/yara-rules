rule Linux_Trojan_Getshell_8a79b859
{
	meta:
		author = "Elastic Security"
		id = "8a79b859-654c-4082-8cfc-61a143671457"
		fingerprint = "5a95d1df94791c8484d783da975bec984fb11653d1f81f6397efd734a042272b"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Getshell"
		reference = "1154ba394176730e51c7c7094ff3274e9f68aaa2ed323040a94e1c6f7fb976a2"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Getshell malware"
		filetype = "executable"

	strings:
		$a = { 0A 00 89 E1 6A 1C 51 56 89 E1 43 6A 66 58 CD 80 B0 66 B3 04 }

	condition:
		all of them
}
