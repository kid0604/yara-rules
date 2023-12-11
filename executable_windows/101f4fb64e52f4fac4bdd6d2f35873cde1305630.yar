rule Windows_Trojan_Bazar_3a2cc53b
{
	meta:
		author = "Elastic Security"
		id = "3a2cc53b-4f73-41f9-aabd-08b8755ba44c"
		fingerprint = "f146d4fff29011acf595f2cba10ed7c3ce6ba07fbda0864d746f8e6355f91add"
		creation_date = "2021-06-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Bazar"
		reference_sample = "b057eb94e711995fd5fd6c57aa38a243575521b11b98734359658a7a9829b417"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Bazar variant with fingerprint 3a2cc53b"
		filetype = "executable"

	strings:
		$a = { 48 63 41 3C 45 33 ED 44 8B FA 48 8B F9 8B 9C 08 88 00 00 00 44 8B A4 08 8C 00 }

	condition:
		all of them
}
