rule Windows_Generic_MalCert_abeefc63
{
	meta:
		author = "Elastic Security"
		id = "abeefc63-ba3d-47b8-ac9d-68df075f3a4c"
		fingerprint = "e31c13d8f259a557a5afe7db6be2c9b4e5a1c3fadeee81c05f6c589dfe87c2a2"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "c070b4fefefe4d3fdce930166f65a43b788eaf24e53bd67d301d920a5c594462"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 41 85 CF D1 37 F9 9E A0 EB 45 46 54 }

	condition:
		all of them
}
