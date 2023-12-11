rule Linux_Cryptominer_Generic_36e404e2
{
	meta:
		author = "Elastic Security"
		id = "36e404e2-be7c-40dc-b861-8ab929cad019"
		fingerprint = "7268b94d67f586ded78ad3a52b23a81fd4edb866fedd0ab1e55997f1bbce4c72"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "59a1d8aa677739f2edbb8bd34f566b31f19d729b0a115fef2eac8ab1d1acc383"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic Linux cryptominer"
		filetype = "executable"

	strings:
		$a = { 61 6C 73 65 20 70 6F 73 69 74 69 76 65 29 1B 5B 30 6D 00 44 45 }

	condition:
		all of them
}
