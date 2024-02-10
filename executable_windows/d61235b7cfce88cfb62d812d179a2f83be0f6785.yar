rule Windows_Generic_Threat_98527d90
{
	meta:
		author = "Elastic Security"
		id = "98527d90-90fb-4428-ab3f-6bbf23139a6e"
		fingerprint = "dac4d9e370992cb4a064d64660801fa165a7e0a1f4a52e9bc3dc286395dcbc91"
		creation_date = "2024-01-24"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "fa24e7c6777e89928afa2a0afb2fab4db854ed3887056b5a76aef42ae38c3c82"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 20 FF D5 48 8D 87 0F 02 00 00 80 20 7F 80 60 28 7F 4C 8D 4C 24 20 4D 8B 01 48 89 DA 48 89 F9 FF D5 48 83 C4 28 5D 5F 5E 5B 48 8D 44 24 80 6A 00 48 39 C4 75 F9 48 83 EC 80 E9 8D 70 FC }

	condition:
		all of them
}
