rule Windows_Trojan_WikiLoader_99681f1c
{
	meta:
		author = "Elastic Security"
		id = "99681f1c-8b32-4cb0-ab6b-640b316e587a"
		fingerprint = "1cd978adc6cbd36a5738fb4c26a2ba4aaa8e69a035bd2618ef2175b3bb2dc4b6"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Trojan.WikiLoader"
		reference_sample = "0b02cfe16ac73f2e7dc52eaf3b93279b7d02b3d64d061782dfed0c55ab621a8e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan WikiLoader"
		filetype = "executable"

	strings:
		$a = { 48 83 EC 08 48 89 E0 4C 89 20 48 83 EC 08 48 89 E0 4C 89 28 48 83 EC 08 48 89 E0 4C 89 30 48 83 EC 08 48 89 E0 4C 89 38 48 89 E5 48 83 EC 08 48 83 EC 60 48 89 CB 48 31 C0 48 89 E9 48 29 E1 48 }

	condition:
		all of them
}
