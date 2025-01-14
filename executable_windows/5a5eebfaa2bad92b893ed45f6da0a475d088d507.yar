rule Windows_Trojan_Lumma_30608a8c
{
	meta:
		author = "Elastic Security"
		id = "30608a8c-f77e-4a86-b4d7-20e339af223b"
		fingerprint = "a8ed2b322f5fab90940227de34ce49cf6f9c0e4c3ae1fd47e55e3bdb6c885ba3"
		creation_date = "2024-10-07"
		last_modified = "2024-10-24"
		threat_name = "Windows.Trojan.Lumma"
		reference_sample = "672e06b9729da0616b103c19d68b812bed33e3e12c788a584f13925f81d68129"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Lumma"
		filetype = "executable"

	strings:
		$a = { 8B 4C 24 04 8B 14 24 31 CA F7 D2 21 CA 29 D0 }
		$b = { 89 F1 C1 E9 0C 80 C9 E0 88 08 89 F1 C1 E9 06 80 E1 3F 80 C9 80 88 48 01 80 E2 3F }

	condition:
		any of them
}
