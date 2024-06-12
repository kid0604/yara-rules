rule Linux_Generic_Threat_cd9ce063
{
	meta:
		author = "Elastic Security"
		id = "cd9ce063-a33b-4771-b7c0-7342d486e15a"
		fingerprint = "e090bd44440e912d04de390c240ca18265bcf49e34f6689b3162e74d2fd31ba4"
		creation_date = "2024-02-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "485581520dd73429b662b73083d504aa8118e01c5d37c1c08b21a5db0341a19d"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 2C 2A 73 74 72 75 63 74 20 7B 20 46 20 75 69 6E 74 70 74 72 3B 20 2E 61 75 74 6F 74 6D 70 5F 32 36 20 2A 74 6C 73 2E 43 6F 6E 6E 20 7D }

	condition:
		all of them
}
