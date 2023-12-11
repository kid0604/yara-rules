rule Linux_Trojan_Xorddos_debb98a1
{
	meta:
		author = "Elastic Security"
		id = "debb98a1-c861-4458-8bff-fae4f00a17dc"
		fingerprint = "2c5688a82f7d39b0fceaf4458856549b1bce695a160a864f41b12b42e86e3745"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "494f549e3dd144e8bcb230dd7b3faa8ff5107d86d9548b21b619a0318e362cad"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { F4 87 5D F4 5B 9C 51 8B 4C 24 04 8D 49 2A 87 4C 24 04 89 4C }

	condition:
		all of them
}
