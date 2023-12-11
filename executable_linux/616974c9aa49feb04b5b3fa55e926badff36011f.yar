rule Linux_Cryptominer_Pgminer_ccf88a37
{
	meta:
		author = "Elastic Security"
		id = "ccf88a37-2a58-40f9-8c13-f1ce218a2ec4"
		fingerprint = "dc82b841a7e72687921c9b14bc86218c3377f939166d11a7cccd885dad4a06e7"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Pgminer"
		reference_sample = "3afc8d2d85aca61108d21f82355ad813eba7a189e81dde263d318988c5ea50bd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Pgminer"
		filetype = "executable"

	strings:
		$a = { F6 41 83 C5 02 48 8B 5D 00 8A 0B 80 F9 2F 76 7E 41 83 FF 0A B8 0A 00 }

	condition:
		all of them
}
