rule Windows_Trojan_Bitrat_54916275
{
	meta:
		author = "Elastic Security"
		id = "54916275-2a0f-4966-956d-7122a4aea9c8"
		fingerprint = "8758b1a839ff801170f6d4ae9186a69af6370f8081defdd25b62e50a3ddcffef"
		creation_date = "2022-08-29"
		last_modified = "2022-09-29"
		threat_name = "Windows.Trojan.Bitrat"
		reference_sample = "d3b2c410b431c006c59f14b33e95c0e44e6221b1118340c745911712296f659f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Bitrat"
		filetype = "executable"

	strings:
		$a1 = { 6A 10 68 50 73 78 00 E8 5F 4D 02 00 8B 7D 08 85 FF 75 0D FF 15 1C 00 6E 00 50 FF 15 68 03 6E 00 }

	condition:
		all of them
}
