rule Linux_Exploit_Sorso_91a4d487
{
	meta:
		author = "Elastic Security"
		id = "91a4d487-cbb6-4805-a4fc-5f4ff3b0e22b"
		fingerprint = "4965d806fa46b74023791ca17a90031753fbbe6094d25868e8d93e720f61d4c0"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Sorso"
		reference_sample = "c0f0a7b45fb91bc18264d901c20539dd32bc03fa5b7d839a0ef5012fb0d895cd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Exploit.Sorso"
		filetype = "executable"

	strings:
		$a = { 80 31 C0 43 53 56 50 B0 5A CD 80 31 C0 50 68 2F }

	condition:
		all of them
}
