rule Linux_Generic_Threat_d60e5924
{
	meta:
		author = "Elastic Security"
		id = "d60e5924-c216-4780-ba61-101abfd94b9d"
		fingerprint = "e5c5833e193c93191783b6b5c7687f5606b1bbe2e7892086246ed883e57c5d15"
		creation_date = "2024-01-18"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "fdcc2366033541053a7c2994e1789f049e9e6579226478e2b420ebe8a7cebcd3"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic threat on Linux systems"
		filetype = "executable"

	strings:
		$a1 = { 2E 2F 6F 76 6C 63 61 70 2F 6D 65 72 67 65 2F 6D 61 67 69 63 }
		$a2 = { 65 78 65 63 6C 20 2F 62 69 6E 2F 62 61 73 68 }

	condition:
		all of them
}
