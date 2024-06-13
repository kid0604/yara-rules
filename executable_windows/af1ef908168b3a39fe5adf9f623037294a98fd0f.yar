rule Windows_Generic_Threat_4b0b73ce
{
	meta:
		author = "Elastic Security"
		id = "4b0b73ce-960d-40ce-ae85-5cf38d949f45"
		fingerprint = "11c544f9f3a51ffcd361d6558754a64a8a38f3ce9385038880ab58c99769db88"
		creation_date = "2024-06-05"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "236fc00cd7c75f70904239935ab90f51b03ff347798f56cec1bdd73a286b24c1"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 53 56 57 8B 7D 08 83 7F 18 00 C6 45 FF C9 74 54 ?? ?? ?? ?? ?? ?? 8D 9B 00 00 00 00 33 F6 83 7F 18 00 74 40 6A 0A FF D3 46 81 FE E8 03 00 00 7C ED 8B 07 8B 50 08 6A 01 8D 4D FF 51 }

	condition:
		all of them
}
