rule Windows_Trojan_Zloader_5dd0a0bf
{
	meta:
		author = "Elastic Security"
		id = "5dd0a0bf-20e4-4c52-b9d9-c157e871b06b"
		fingerprint = "06545df6c556adf8a6844724e77d005c0299b544f21df2ea44bb9679964dbb9f"
		creation_date = "2022-03-03"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Zloader"
		reference_sample = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Zloader variant with fingerprint 5dd0a0bf"
		filetype = "executable"

	strings:
		$a = { B6 08 89 CA 80 C2 F7 80 FA 05 72 F2 80 F9 20 74 ED 03 5D 0C 8D }

	condition:
		all of them
}
