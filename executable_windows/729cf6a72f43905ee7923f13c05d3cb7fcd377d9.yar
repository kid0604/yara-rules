rule Windows_Generic_Threat_820fe9c9
{
	meta:
		author = "Elastic Security"
		id = "820fe9c9-2abc-4dd5-84e2-a74fbded4dc6"
		fingerprint = "e43f4fee9e23233bf8597decac79bda4790b5682f5e0fe86e3a13cb18724ea3e"
		creation_date = "2024-01-11"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "1102a499b8a863bdbfd978a1d17270990e6b7fe60ce54b9dd17492234aad2f8c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 2E 2A 73 74 72 75 63 74 20 7B 20 46 20 75 69 6E 74 70 74 72 3B 20 58 30 20 63 68 61 6E 20 73 74 72 69 6E 67 3B 20 58 31 20 62 6F 6F 6C 20 7D }

	condition:
		all of them
}
