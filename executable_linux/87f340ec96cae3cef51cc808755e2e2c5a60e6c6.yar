rule Linux_Trojan_Xorddos_ba961ed2
{
	meta:
		author = "Elastic Security"
		id = "ba961ed2-b410-4da5-8452-a03cf5f59808"
		fingerprint = "fff4804164fb9ff1f667d619b6078b00a782b81716e217ad2c11df80cb8677aa"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "45f25d2ffa2fc2566ed0eab6bdaf6989006315bbbbc591288be39b65abf2410b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { F8 C9 C3 55 89 E5 83 EC 38 C7 45 F8 FF FF FF FF C7 45 FC FF FF }

	condition:
		all of them
}
