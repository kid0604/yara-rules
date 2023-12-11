rule Linux_Trojan_Tsunami_0fa3a6e9
{
	meta:
		author = "Elastic Security"
		id = "0fa3a6e9-89f3-4bc8-8dc1-e9ccbeeb836d"
		fingerprint = "fed796c5275e2e91c75dcdbf73d0c0ab37591115989312c6f6c5adcd138bc91f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "40a15a186373a062bfb476b37a73c61e1ba84e5fa57282a7f9ec0481860f372a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Tsunami malware"
		filetype = "executable"

	strings:
		$a = { EC 8B 55 EC C1 FA 10 0F B7 45 EC 01 C2 89 55 EC 8B 45 EC C1 }

	condition:
		all of them
}
