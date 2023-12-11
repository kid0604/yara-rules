rule Linux_Trojan_Xorddos_56bd04d3
{
	meta:
		author = "Elastic Security"
		id = "56bd04d3-6b52-43f4-b170-637feb86397a"
		fingerprint = "25cd85e8e65362a993a314f2fc500266fce2f343d21a2e91b146dafbbe8186db"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "0d2ce3891851808fb36779a348a83bf4aa9de1a2b2684fd0692434682afac5ec"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { 5C 87 5C 24 04 89 5C 24 04 8B 1C 24 8D 64 24 04 8B 00 8B F6 87 }

	condition:
		all of them
}
