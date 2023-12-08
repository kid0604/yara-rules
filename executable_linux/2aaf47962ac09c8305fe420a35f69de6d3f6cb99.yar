rule Linux_Trojan_Rekoobe_de9e7bdf
{
	meta:
		author = "Elastic Security"
		id = "de9e7bdf-c515-4af8-957a-e489b7cb9716"
		fingerprint = "ab3f0b9179a136f7c1df43234ba3635284663dee89f4e48d9dfc762fb762f0db"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Rekoobe"
		reference_sample = "447da7bee72c98c2202f1919561543e54ec1b9b67bd67e639b9fb6e42172d951"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Rekoobe malware"
		filetype = "executable"

	strings:
		$a = { F5 48 89 D6 48 C1 EE 18 40 0F B6 F6 48 33 2C F1 48 89 D6 48 C1 }

	condition:
		all of them
}
