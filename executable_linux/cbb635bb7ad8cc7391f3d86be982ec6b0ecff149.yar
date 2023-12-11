rule Linux_Trojan_Dropperl_e2443be5
{
	meta:
		author = "Elastic Security"
		id = "e2443be5-da15-4af2-b090-bf5accf2a844"
		fingerprint = "e49acaa476bd669b40ccc82a7d3a01e9c421e6709ecbfe8d0e24219677c96339"
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
		$a = { 45 F0 75 DB EB 17 48 8B 45 F8 48 83 C0 08 48 8B 10 48 8B 45 F8 48 }

	condition:
		all of them
}
