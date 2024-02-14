rule Linux_Generic_Threat_ea5ade9a
{
	meta:
		author = "Elastic Security"
		id = "ea5ade9a-101e-49df-b0e8-45a04320950b"
		fingerprint = "fedf3b94c22a1dab3916b7bc6a1b88768c0debd6d628b78d8a6610b636f3c652"
		creation_date = "2024-01-17"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "d75189d883b739d9fe558637b1fab7f41e414937a8bae7a9d58347c223a1fcaa"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 89 E5 53 8B 5D 08 B8 0D 00 00 00 CD 80 8B 5D FC 89 EC 5D C3 55 89 E5 53 8B 5D 08 B8 2D 00 00 00 CD 80 8B 5D FC 89 EC 5D C3 55 89 E5 53 8B 5D 08 8B 4D 0C B8 6C 00 00 00 CD 80 8B 5D FC 89 EC }

	condition:
		all of them
}
