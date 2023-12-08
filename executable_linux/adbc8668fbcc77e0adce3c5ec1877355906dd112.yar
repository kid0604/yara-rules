rule Linux_Cryptominer_Malxmr_033f06dd
{
	meta:
		author = "Elastic Security"
		id = "033f06dd-f3ed-4140-bbff-138ed2d8378c"
		fingerprint = "2f1f39e10df0ca6c133237b6d92afcb8a9c23de511120e8860c1e6ed571252ed"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		reference_sample = "3afc8d2d85aca61108d21f82355ad813eba7a189e81dde263d318988c5ea50bd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { 42 68 63 33 4E 33 5A 48 78 6A 64 58 51 67 4C 57 51 36 49 43 31 }

	condition:
		all of them
}
