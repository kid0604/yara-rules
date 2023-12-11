rule Windows_Trojan_Clipbanker_b60a50b8
{
	meta:
		author = "Elastic Security"
		id = "b60a50b8-91a4-49a7-bd05-fa4cc1dee1ac"
		fingerprint = "097bb88d8482a4915c19affc82750c7ee225b89f2611ea654cfc3c044aae0738"
		creation_date = "2022-02-28"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Clipbanker"
		reference_sample = "02b06acb113c31f5a2ac9c99f9614e0fab0f78afc5ae872e46bae139c2c9b1f6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Clipbanker"
		filetype = "executable"

	strings:
		$a1 = { 40 66 0F F8 C1 0F 11 40 A0 0F 10 84 15 08 FF FF FF 83 C2 40 }

	condition:
		all of them
}
