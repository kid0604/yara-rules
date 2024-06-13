rule Windows_Generic_Threat_5e33bb4b
{
	meta:
		author = "Elastic Security"
		id = "5e33bb4b-830e-4814-b6cf-d5e5b4da7ada"
		fingerprint = "a08b9db015f1b6f62252d456b1b0cd0fdec1e19cdd2bc1400fe2bf76150ea07b"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "13c06d7b030a46c6bb6351f40184af9fafaf4c67b6a2627a45925dd17501d659"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 43 3A 5C 55 73 65 72 73 5C 61 64 6D 69 6E 5C 44 65 73 6B 74 6F 70 5C 57 6F 72 6B 5C 46 69 6C 65 49 6E 73 74 61 6C 6C 65 72 5C 52 65 6C 65 61 73 65 5C 46 69 6C 65 49 6E 73 74 61 6C 6C 65 72 2E 70 64 62 }

	condition:
		all of them
}
