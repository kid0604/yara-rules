rule Windows_Trojan_CobaltStrike_4106070a
{
	meta:
		author = "Elastic Security"
		id = "4106070a-24e2-421b-ab83-67b817a9f019"
		fingerprint = "c12b919064a9cd2a603c134c5f73f6d05ffbf4cbed1e5b5246687378102e4338"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "98789a11c06c1dfff7e02f66146afca597233c17e0d4900d6a683a150f16b3a4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan CobaltStrike"
		filetype = "executable"

	strings:
		$a1 = { 48 8B 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 }
		$a2 = { 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 F8 0A }

	condition:
		all of them
}
