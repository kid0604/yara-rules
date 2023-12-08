rule Linux_Trojan_Gafgyt_f51c5ac3
{
	meta:
		author = "Elastic Security"
		id = "f51c5ac3-ade9-4d01-b578-3473a2b116db"
		fingerprint = "34f254afdf94b1eb29bae4eb8e3864ea49e918a5dbe6e4c9d06a4292c104a792"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt with fingerprint f51c5ac3"
		filetype = "executable"

	strings:
		$a = { 74 2A 8B 45 0C 0F B6 00 84 C0 74 17 8B 45 0C 40 89 44 24 04 8B }

	condition:
		all of them
}
