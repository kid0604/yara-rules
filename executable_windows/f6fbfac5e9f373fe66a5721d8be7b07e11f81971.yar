rule Windows_Generic_Threat_046aa1ec
{
	meta:
		author = "Elastic Security"
		id = "046aa1ec-5134-4a03-85c2-048b5d363484"
		fingerprint = "46591671500f83b6627a17368a0bbe43650da1dd58ba1a136a47818fe685bc68"
		creation_date = "2024-02-20"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "c74cf499fb9298d43a6e64930addb1f8a8d8336c796b9bc02ffc260684ec60a2"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 C4 F4 D9 7D FE 66 8B 45 FE 80 CC 0C 66 89 45 FC D9 6D FC DF 7D F4 D9 6D FE 8B 45 F4 8B 55 F8 8B E5 5D C3 55 8B EC 51 33 D2 8D 5D 08 8B 03 83 C3 04 85 C0 74 03 03 50 04 49 75 F1 85 }

	condition:
		all of them
}
