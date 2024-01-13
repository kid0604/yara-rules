rule Windows_Generic_Threat_62e1f5fc
{
	meta:
		author = "Elastic Security"
		id = "62e1f5fc-325b-46e0-8c03-1a73e873ab16"
		fingerprint = "64839df90109a0c706c0a3626ba6c4c2eaa5dcd564f0e9889ab9ad4f12e150fe"
		creation_date = "2024-01-07"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "4a692e244a389af0339de8c2d429b541d6d763afb0a2b1bb20bee879330f2f42"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 43 6C 69 65 6E 74 2E 48 61 6E 64 6C 65 5F 50 61 63 6B 65 74 }
		$a2 = { 67 65 74 5F 73 45 78 70 59 65 61 72 }
		$a3 = { 73 65 74 5F 73 45 78 70 59 65 61 72 }

	condition:
		all of them
}
