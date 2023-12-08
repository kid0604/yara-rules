rule Linux_Trojan_Xorddos_2084099a
{
	meta:
		author = "Elastic Security"
		id = "2084099a-1df6-4481-9d13-3a5bd6a53817"
		fingerprint = "dfb813a5713f0e7bdb5afd500f1e84c6f042c8b1a1d27dd6511dca7f2107c13b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Xorddos"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { 8B 45 FC 8B 50 18 8B 45 08 89 50 18 8B 45 FC 8B 40 08 85 C0 }

	condition:
		all of them
}
