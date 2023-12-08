rule Linux_Trojan_Gafgyt_1b2e2a3a
{
	meta:
		author = "Elastic Security"
		id = "1b2e2a3a-1302-41c7-be99-43edb5563294"
		fingerprint = "6f24b67d0a6a4fc4e1cfea5a5414b82af1332a3e6074eb2178aee6b27702b407"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant 1b2e2a3a"
		filetype = "executable"

	strings:
		$a = { 83 7D 18 00 74 25 8B 45 1C 83 E0 02 85 C0 74 1B C7 44 24 04 2D 00 }

	condition:
		all of them
}
