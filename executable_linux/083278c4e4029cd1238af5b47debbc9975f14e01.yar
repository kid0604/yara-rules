rule Linux_Trojan_Generic_1c5e42b7
{
	meta:
		author = "Elastic Security"
		id = "1c5e42b7-b873-443e-a30c-66a75fc39b21"
		fingerprint = "b64284e1220ec9abc9b233e513020f8b486c76f91e4c3f2a0a6fb003330c2535"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "b078a02963610475217682e6e1d6ae0b30935273ed98743e47cc2553fbfd068f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic"
		filetype = "executable"

	strings:
		$a = { 89 C0 89 45 F4 83 7D F4 FF 75 1C 83 EC 0C 68 }

	condition:
		all of them
}
