rule Windows_Generic_Threat_ce98c4bc
{
	meta:
		author = "Elastic Security"
		id = "ce98c4bc-22bb-4c2b-bced-8fc36bd3a2f0"
		fingerprint = "d0849208c71c1845a6319052474549dba8514ecf7efe6185c1af22ad151bdce7"
		creation_date = "2023-12-17"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "950e8a29f516ef3cf1a81501e97fbbbedb289ad9fb93352edb563f749378da35"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 4D 65 73 73 61 67 65 50 61 63 6B 4C 69 62 2E 4D 65 73 73 61 67 65 50 61 63 6B }
		$a2 = { 43 6C 69 65 6E 74 2E 41 6C 67 6F 72 69 74 68 6D }

	condition:
		all of them
}
