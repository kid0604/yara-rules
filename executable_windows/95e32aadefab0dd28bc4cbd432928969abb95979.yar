rule Windows_Generic_MalCert_eb360bb1
{
	meta:
		author = "Elastic Security"
		id = "eb360bb1-bb05-4a0f-8e79-2bd9303b7790"
		fingerprint = "e463fe324a2d5280c0063d4279eecea1a425b88d392f6a8c9d95d14f68ba4fd5"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "09003df4deacc194a94c0def0f5aa8a3a8d612ea68d5e6b4b4c5162f208886e0"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 4C 03 54 CE 17 E2 C3 64 2C 3D 06 4C }

	condition:
		all of them
}
