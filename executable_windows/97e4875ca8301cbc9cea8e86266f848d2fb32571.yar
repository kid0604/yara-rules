rule Windows_Trojan_Dridex_63ddf193
{
	meta:
		author = "Elastic Security"
		id = "63ddf193-31a6-4139-b452-960fe742da93"
		fingerprint = "7b4c5fde8e107a67ff22f3012200e56ec452e0a57a49edb2e06ee225ecfe228c"
		creation_date = "2021-08-07"
		last_modified = "2021-10-04"
		threat_name = "Windows.Trojan.Dridex"
		reference_sample = "b1d66350978808577159acc7dc7faaa273e82c103487a90bf0d040afa000cb0d"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Dridex variant 63ddf193"
		filetype = "executable"

	strings:
		$a1 = "snxhk.dll" ascii fullword
		$a2 = "LondLibruryA" ascii fullword

	condition:
		all of them
}
