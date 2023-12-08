rule Linux_Trojan_Mirai_26cba88c
{
	meta:
		author = "Elastic Security"
		id = "26cba88c-7bd4-4fac-b395-04c4745fee43"
		fingerprint = "358dd5d916fec3e1407c490ce0289886985be8fabee49581afbc01dcf941733e"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "4b4758bff3dcaa5640e340d27abba5c2e2b02c3c4a582374e183986375e49be8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with ID 26cba88c"
		filetype = "executable"

	strings:
		$a = { F6 41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4A 00 }

	condition:
		all of them
}
