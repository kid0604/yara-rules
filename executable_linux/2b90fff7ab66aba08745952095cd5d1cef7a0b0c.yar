rule Linux_Trojan_Dropperl_b97baf37
{
	meta:
		author = "Elastic Security"
		id = "b97baf37-48db-4eb7-85c7-08e75054bea7"
		fingerprint = "0852f1afa6162d14b076a3fc1f56e4d365b5d0e8932bae6ab055000cca7d1fba"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Dropperl"
		reference_sample = "aff94f915fc81d5a2649ebd7c21ec8a4c2fc0d622ec9b790b43cc49f7feb83da"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Dropperl"
		filetype = "executable"

	strings:
		$a = { 12 48 89 10 83 45 DC 01 83 45 D8 01 8B 45 D8 3B 45 BC 7C CF 8B }

	condition:
		all of them
}
