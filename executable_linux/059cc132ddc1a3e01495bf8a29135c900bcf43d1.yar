rule Linux_Cryptominer_Uwamson_c42fd06d
{
	meta:
		author = "Elastic Security"
		id = "c42fd06d-b9ab-4f1f-bb59-e7b49355115c"
		fingerprint = "dac171e66289e2222cd631d616f31829f31dfeeffb34f0e1dcdd687d294f117c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Uwamson"
		reference_sample = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Uwamson malware"
		filetype = "executable"

	strings:
		$a = { F0 4C 89 F3 48 8B 34 24 48 C1 E0 04 48 C1 E3 07 48 8B 7C 24 10 48 }

	condition:
		all of them
}
