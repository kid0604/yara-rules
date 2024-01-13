rule Windows_Generic_Threat_e96f9e97
{
	meta:
		author = "Elastic Security"
		id = "e96f9e97-cb44-42e5-a06b-98775cbb1f2f"
		fingerprint = "2277fb0b58f923d394f5d4049b6049e66f99aff4ac874849bdc1877b9c6a0d3e"
		creation_date = "2024-01-01"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "bfbab69e9fc517bc46ae88afd0603a498a4c77409e83466d05db2797234ea7fc"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 7A 47 4D 5E 5A 4D 5D 4B 7D 6D 4A 41 57 4B 54 49 5F 4C 67 6D 54 52 5B 51 46 43 6F 71 40 46 45 53 67 7C 5D 6F }

	condition:
		all of them
}
