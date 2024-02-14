rule Linux_Generic_Threat_d7802b0a
{
	meta:
		author = "Elastic Security"
		id = "d7802b0a-2286-48c8-a0b5-96af896b384e"
		fingerprint = "105112354dea4db98d295965d4816c219b049fe7b8b714f8dc3d428058a41a32"
		creation_date = "2024-01-18"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "a2b54f789a1c4cbed13e0e2a5ab61e0ce5bb42d44fe52ad4b7dd3da610045257"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 48 81 EC 88 00 00 00 48 89 AC 24 80 00 00 00 48 8D AC 24 80 00 00 00 49 C7 C5 00 00 00 00 4C 89 6C 24 78 88 8C 24 A8 00 00 00 48 89 9C 24 A0 00 00 00 48 89 84 24 98 00 00 00 C6 44 24 27 00 90 }

	condition:
		all of them
}
