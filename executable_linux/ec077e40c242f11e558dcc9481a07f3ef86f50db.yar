rule Linux_Trojan_Generic_7a95ef79
{
	meta:
		author = "Elastic Security"
		id = "7a95ef79-3df5-4f7a-a8ba-00577473b288"
		fingerprint = "aadec0fa964f94afb725a568dacf21e80b80d359cc5dfdd8d028aaece04c7012"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "f59340a740af8f7f4b96e3ea46d38dbe81f2b776820b6f53b7028119c5db4355"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic 7a95ef79"
		filetype = "executable"

	strings:
		$a = { 1C 8B 54 24 20 8B 74 24 24 CD 80 5E 5A 59 5B C3 }

	condition:
		all of them
}
