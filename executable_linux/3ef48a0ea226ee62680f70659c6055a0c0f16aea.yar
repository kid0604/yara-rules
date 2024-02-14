rule Linux_Generic_Threat_98bbca63
{
	meta:
		author = "Elastic Security"
		id = "98bbca63-68c4-4b32-8cb6-50f9dad0a8f2"
		fingerprint = "d10317a1a09e86b55eb7b00a87cb010e0d2f11ade2dccc896aaeba9819bd6ca5"
		creation_date = "2024-01-22"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "1d4d3d8e089dcca348bb4a5115ee2991575c70584dce674da13b738dd0d6ff98"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 64 65 73 63 72 69 70 74 69 6F 6E 3D 4C 4B 4D 20 72 6F 6F 74 6B 69 74 }
		$a2 = { 61 75 74 68 6F 72 3D 6D 30 6E 61 64 }

	condition:
		all of them
}
