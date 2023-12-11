rule Windows_Trojan_Amadey_7abb059b
{
	meta:
		author = "Elastic Security"
		id = "7abb059b-4001-4eec-8185-1e0497e15062"
		fingerprint = "686ae7cf62941d7db051fa8c45f0f7a27440fa0fdc5f0919c9667dfeca46ca1f"
		creation_date = "2021-06-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Amadey"
		reference_sample = "33e6b58ce9571ca7208d1c98610005acd439f3e37d2329dae8eb871a2c4c297e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Amadey"
		filetype = "executable"

	strings:
		$a = { 18 83 78 14 10 72 02 8B 00 6A 01 6A 00 6A 00 6A 00 6A 00 56 }

	condition:
		all of them
}
