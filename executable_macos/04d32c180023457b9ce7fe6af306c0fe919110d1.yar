rule MacOS_Virus_Vsearch_2a0419f8
{
	meta:
		author = "Elastic Security"
		id = "2a0419f8-95b2-4f87-a37a-ee0b65e344e9"
		fingerprint = "2da9f0fc05bc8e23feb33b27142f46fb437af77766e39889a02ea843d52d17eb"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Virus.Vsearch"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Virus.Vsearch"
		filetype = "executable"

	strings:
		$a = { 6F 72 6D 61 6C 2F 69 33 38 36 2F 56 53 44 6F 77 6E 6C 6F 61 64 65 72 2E 6F 00 }

	condition:
		all of them
}
