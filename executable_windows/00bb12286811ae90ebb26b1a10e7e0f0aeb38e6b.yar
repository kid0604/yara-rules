rule Windows_Generic_Threat_51a52b44
{
	meta:
		author = "Elastic Security"
		id = "51a52b44-025b-4068-89eb-01cdf66efb4e"
		fingerprint = "b10f3a3ceab827482139a9cadbd4507767e4d941191a7f19af517575435a5f70"
		creation_date = "2024-01-21"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "303aafcc660baa803344bed6a3a7a5b150668f88a222c28182db588fc1e744e0"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 40 6A 67 72 72 6C 6E 68 6D 67 65 77 77 68 74 69 63 6F 74 6D 6C 77 6E 74 6A 6A 71 68 72 68 62 74 75 64 72 78 7A 63 72 67 65 78 65 70 71 73 7A 73 75 78 6B 68 6E 79 63 74 72 63 63 7A 6D 63 63 69 63 61 61 68 70 66 }

	condition:
		all of them
}
