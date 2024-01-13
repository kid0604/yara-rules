rule Windows_Generic_Threat_005fd471
{
	meta:
		author = "Elastic Security"
		id = "005fd471-d968-4ece-a61d-91beac4c1e34"
		fingerprint = "30afbb04c257c20ccd2cff15f893715187b7e7b66a9c9f09d076d21466e25a57"
		creation_date = "2024-01-01"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "502814ed565a923da15626d46fde8cc7fd422790e32b3cad973ed8ec8602b228"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 5F 3F 44 4B 4B 66 25 37 2A 5E 70 42 70 }
		$a2 = { 71 5A 3E 7D 6F 5D 6E 2D 74 48 5E 55 55 22 3C }
		$a3 = { 3E 2D 21 47 45 6A 3C 33 23 47 5B 51 }

	condition:
		all of them
}
