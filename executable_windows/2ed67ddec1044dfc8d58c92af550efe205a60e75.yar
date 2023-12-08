rule Windows_Trojan_Dridex_c6f01353
{
	meta:
		author = "Elastic Security"
		id = "c6f01353-cf55-4eac-9f25-6f9cce3b7990"
		fingerprint = "fbdb230032e3655448d26a679afc612c79d33ac827bcd834e54fe5c05f04d828"
		creation_date = "2021-08-07"
		last_modified = "2021-10-04"
		threat_name = "Windows.Trojan.Dridex"
		reference_sample = "739682ccb54170e435730c54ba9f7e09f32a3473c07d2d18ae669235dcfe84de"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Dridex with fingerprint c6f01353"
		filetype = "executable"

	strings:
		$a1 = { 56 57 55 8B FA 85 C9 74 58 85 FF 74 54 0F B7 37 85 F6 75 04 }

	condition:
		all of them
}
