rule Windows_Generic_Threat_5e718a0c
{
	meta:
		author = "Elastic Security"
		id = "5e718a0c-3c46-46f7-adfd-b0c3c75b865f"
		fingerprint = "b6f9b85f4438c3097b430495dee6ceef1a88bd5cece823656d9dd325e8d9d4a1"
		creation_date = "2024-01-03"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "430b9369b779208bd3976bd2adc3e63d3f71e5edfea30490e6e93040c1b3bac6"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 44 3A 28 41 3B 3B 30 78 30 30 31 46 30 30 30 33 3B 3B 3B 42 41 29 28 41 3B 3B 30 78 30 30 31 30 30 30 30 33 3B 3B 3B 41 55 29 }

	condition:
		all of them
}
