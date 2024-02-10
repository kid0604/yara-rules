rule Windows_Generic_Threat_deb82e8c
{
	meta:
		author = "Elastic Security"
		id = "deb82e8c-57dc-47ea-a786-b4e1ae41a40f"
		fingerprint = "3429ecf8f509c6833b790156e61f0d1a6e0dc259d4891d6150a99b5cb3f0f26e"
		creation_date = "2024-01-31"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "0f5791588a9898a3db29326785d31b52b524c3097370f6aa28564473d353cd38"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 50 6F 76 65 72 74 79 20 69 73 20 74 68 65 20 70 61 72 65 6E 74 20 6F 66 20 63 72 69 6D 65 2E }
		$a2 = { 2D 20 53 79 73 74 65 6D 4C 61 79 6F 75 74 20 25 64 }

	condition:
		all of them
}
