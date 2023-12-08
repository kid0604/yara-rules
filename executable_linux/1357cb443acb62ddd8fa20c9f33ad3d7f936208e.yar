rule Linux_Exploit_Lotoor_c5983669
{
	meta:
		author = "Elastic Security"
		id = "c5983669-67d6-4a9e-945f-aae383211872"
		fingerprint = "1d74ddacc623a433f84b1ab6e74bcfc0e69afb29f40a8b2d660d96a88610c3b2"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "d08be92a484991afae3567256b6cec60a53400e0e9b6f6b4d5c416a22ccca1cf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { 48 83 C0 58 48 89 44 24 20 48 8B 44 24 18 48 89 C7 BA 60 00 }

	condition:
		all of them
}
