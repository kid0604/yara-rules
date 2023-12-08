rule Windows_Trojan_Smokeloader_3687686f
{
	meta:
		author = "Elastic Security"
		id = "3687686f-8fbf-4f09-9afa-612ee65dc86c"
		fingerprint = "0f483f9f79ae29b944825c1987366d7b450312f475845e2242a07674580918bc"
		creation_date = "2021-07-21"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Smokeloader"
		reference_sample = "8b3014ecd962a335b246f6c70fc820247e8bdaef98136e464b1fdb824031eef7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Smokeloader"
		filetype = "executable"

	strings:
		$a = { 0C 8B 45 F0 89 45 C8 8B 45 C8 8B 40 3C 8B 4D F0 8D 44 01 04 89 }

	condition:
		all of them
}
