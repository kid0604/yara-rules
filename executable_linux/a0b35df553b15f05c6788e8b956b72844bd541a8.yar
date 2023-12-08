rule Linux_Trojan_Mirai_3acd6ed4
{
	meta:
		author = "Elastic Security"
		id = "3acd6ed4-6d62-47af-8d80-d5465abce38a"
		fingerprint = "e787989c37c26d4bb79c235150a08bbf3c4c963e2bc000f9a243a09bbf1f59cb"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "2644447de8befa1b4fe39b2117d49754718a2f230d6d5f977166386aa88e7b84"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint 3acd6ed4"
		filetype = "executable"

	strings:
		$a = { E5 7E 44 4C 89 E3 31 FF 48 C1 E3 05 48 03 5D 38 48 89 2B 44 88 }

	condition:
		all of them
}
