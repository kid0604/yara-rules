rule Windows_Generic_Threat_5be3a474
{
	meta:
		author = "Elastic Security"
		id = "5be3a474-d12f-489f-a2a7-87d29687e2e6"
		fingerprint = "8b220ea86ad3bbdcf6e2f976dc0bb84c1eb8cb1f3ad46ab5c9d19289952c912b"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "b902954d634307260d5bd8fb6248271f933c1cbc649aa2073bf05e79c1aedb66"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 53 56 57 8B F9 33 F6 8D 5F 02 66 8B 07 83 C7 02 66 3B C6 75 F5 8A 01 2B FB D1 FF 8D 5F FF 85 DB 7E 23 0F B6 F8 83 C1 02 66 8B 01 8D 49 02 66 2B C7 C7 45 FC 00 08 00 00 66 2B 45 FC }

	condition:
		all of them
}
