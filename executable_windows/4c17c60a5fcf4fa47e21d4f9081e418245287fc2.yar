rule Windows_Trojan_Qbot_92c67a6d
{
	meta:
		author = "Elastic Security"
		id = "92c67a6d-9290-4cd9-8123-7dace2cf333d"
		fingerprint = "4719993107243a22552b65e6ec8dc850842124b0b9919a6ecaeb26377a1a5ebd"
		creation_date = "2021-02-16"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Qbot"
		reference_sample = "636e2904276fe33e10cce5a562ded451665b82b24c852cbdb9882f7a54443e02"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Qbot with fingerprint 92c67a6d"
		filetype = "executable"

	strings:
		$a = { 33 C0 59 85 F6 74 2D 83 66 0C 00 40 89 06 6A 20 89 46 04 C7 46 08 08 00 }

	condition:
		all of them
}
