rule Windows_Generic_Threat_a440f624
{
	meta:
		author = "Elastic Security"
		id = "a440f624-c7ec-4f26-bfb5-982bae5f6887"
		fingerprint = "0f538f8f4eb2e71fb74d8305a179fc2ad880ab5a4cfd37bd35b5da2629ed892c"
		creation_date = "2024-01-07"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "3564fec3d47dfafc7e9c662654865aed74aedeac7371af8a77e573ea92cbd072"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 2E 20 49 50 20 3D 20 25 73 2C 20 50 6F 72 74 20 3D 20 25 64 2C 20 73 6B 20 3D 20 25 64 }
		$a2 = { 2E 20 49 50 20 3D 20 25 73 2C 20 50 6F 72 74 20 3D 20 25 64 2C 20 4C 65 6E 20 3D 20 25 64 }

	condition:
		all of them
}
