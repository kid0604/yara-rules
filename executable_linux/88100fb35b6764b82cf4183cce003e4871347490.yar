rule Linux_Generic_Threat_6bed4416
{
	meta:
		author = "Elastic Security"
		id = "6bed4416-18fe-4416-a6ee-89d269922347"
		fingerprint = "f9d39e6aa9f8b005ff156923c68d215dabf2db79bd7d4a3dccb9ead8f1a28d88"
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
		$a1 = { 61 64 78 61 65 73 61 76 78 62 69 6E 63 67 6F 64 69 72 64 6E 73 65 6E 64 66 69 6E 66 6D 61 66 74 70 67 63 20 67 70 20 69 6E 20 69 6E 74 6D 61 70 6E 69 6C 6F 62 6A 70 63 3D 70 74 72 73 65 74 73 68 61 73 73 68 74 63 70 75 64 70 }

	condition:
		all of them
}
