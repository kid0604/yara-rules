rule Windows_Generic_Threat_0a640296
{
	meta:
		author = "Elastic Security"
		id = "0a640296-0813-4cd3-b55b-01b3689e73d9"
		fingerprint = "3fa8712dbf0cdb0581fc312bcfa2e9ea50e04cccba6dc93f377c1b64e96784aa"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "3682eff62caaf2c90adef447d3ff48a3f9c34c571046f379d2eaf121976f1d07"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 28 00 00 0A 02 7B 0F 00 00 04 6F 29 00 00 0A 7D 10 00 00 04 02 7B 10 00 00 04 28 2A 00 00 0A 00 02 7B 08 00 00 04 7B 03 00 00 04 02 7B 10 00 00 04 6F 2B 00 00 0A 16 FE 01 0D 09 39 29 01 00 00 }

	condition:
		all of them
}
