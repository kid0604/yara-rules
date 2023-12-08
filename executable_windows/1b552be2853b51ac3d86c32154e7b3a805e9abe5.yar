rule Windows_Trojan_Lokibot_0f421617
{
	meta:
		author = "Elastic Security"
		id = "0f421617-df2b-4cb5-9d10-d984f6553012"
		fingerprint = "9ff5d594428e4a5de84f0142dfa9f54cb75489192461deb978c70f1bdc88acda"
		creation_date = "2021-07-20"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Lokibot"
		reference_sample = "de6200b184832e7d3bfe00c193034192774e3cfca96120dc97ad6fed1e472080"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Lokibot with ID 0f421617"
		filetype = "executable"

	strings:
		$a = { 08 8B CE 0F B6 14 38 D3 E2 83 C1 08 03 F2 48 79 F2 5F 8B C6 }

	condition:
		all of them
}
