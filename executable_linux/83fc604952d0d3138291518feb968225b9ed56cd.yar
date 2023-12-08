rule Linux_Trojan_Xorddos_30f3b4d4
{
	meta:
		author = "Elastic Security"
		id = "30f3b4d4-e634-418e-a9d5-7f12ef22f9ac"
		fingerprint = "de1002eb8e9aae984ee5fe2a6c1f91845dab4861e09e01d644248cff8c590e5b"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "5b15d43d3535965ec9b84334cf9def0e8c3d064ffc022f6890320cd6045175bc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { 24 70 9C 83 C5 17 9D 8D 6D E9 0F 10 74 24 60 8B F6 0F 10 6C }

	condition:
		all of them
}
