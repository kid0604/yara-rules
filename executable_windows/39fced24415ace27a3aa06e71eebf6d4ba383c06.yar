rule Windows_Generic_Threat_dbae6542
{
	meta:
		author = "Elastic Security"
		id = "dbae6542-b343-4320-884c-c0ce97a431f1"
		fingerprint = "880aafd423494eccab31342bdfec392fdf4a7b4d98614a0c3b5302d62bcf5ba8"
		creation_date = "2024-01-10"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "c73f533f96ed894b9ff717da195083a594673e218ee9a269e360353b9c9a0283"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 28 00 00 0A 20 B8 0B 00 00 20 10 27 00 00 6F 29 00 00 0A 28 1F 00 00 0A 7E 0F 00 00 04 2D 0A 28 27 00 00 06 28 19 00 00 06 7E 15 00 00 04 6F 2A 00 00 0A 26 17 2D C8 2A EE 16 80 0F 00 00 04 14 }

	condition:
		all of them
}
