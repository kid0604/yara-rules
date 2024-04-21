rule Windows_Generic_Threat_11a56097
{
	meta:
		author = "Elastic Security"
		id = "11a56097-c019-43dc-b401-c3bd5e88ce17"
		fingerprint = "37fda03cc0d50dc8bf6adfb83369649047e73fe33929f6579bf806b343eb092c"
		creation_date = "2024-01-12"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "98d538c8f074d831b7a91e549e78f6549db5d2c53a10dbe82209d15d1c2e9b56"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat based on specific file signatures"
		filetype = "executable"

	strings:
		$a1 = { 6E 6F 69 74 70 65 63 78 45 74 61 6D 72 6F 46 65 67 61 6D 49 64 61 42 }
		$a2 = { 65 74 75 62 69 72 74 74 41 65 74 65 6C 6F 73 62 4F }

	condition:
		all of them
}
