rule Windows_Generic_Threat_54b0ec47
{
	meta:
		author = "Elastic Security"
		id = "54b0ec47-79f3-4187-8253-805e7ad102ce"
		fingerprint = "2c3890010aad3c2b54cba08a62b5af6a678849a6b823627bf9e26c8693a89c60"
		creation_date = "2024-01-03"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "9c14203069ff6003e7f408bed71e75394de7a6c1451266c59c5639360bf5718c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 2D 2D 2D 2D 3D 5F 25 73 5F 25 2E 33 75 5F 25 2E 34 75 5F 25 2E 38 58 2E 25 2E 38 58 }
		$a2 = { 25 73 2C 20 25 75 20 25 73 20 25 75 20 25 2E 32 75 3A 25 2E 32 75 3A 25 2E 32 75 20 25 63 25 2E 32 75 25 2E 32 75 }

	condition:
		all of them
}
