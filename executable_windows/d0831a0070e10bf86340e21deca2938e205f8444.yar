rule Windows_Trojan_Donutloader_5c38878d
{
	meta:
		author = "Elastic Security"
		id = "5c38878d-ca94-4fd9-a36e-1ae5fe713ca2"
		fingerprint = "3b55ec6c37891880b53633b936d10f94d2b806db1723875e4ac95f8a34d97150"
		creation_date = "2021-09-15"
		last_modified = "2021-01-13"
		threat_name = "Windows.Trojan.Donutloader"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Donutloader"
		filetype = "executable"

	strings:
		$a = { 24 48 03 C2 48 89 44 24 28 41 8A 00 84 C0 74 14 33 D2 FF C1 }

	condition:
		any of them
}
