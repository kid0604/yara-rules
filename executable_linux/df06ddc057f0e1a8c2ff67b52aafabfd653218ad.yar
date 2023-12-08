rule Linux_Trojan_Mobidash_ddca1181
{
	meta:
		author = "Elastic Security"
		id = "ddca1181-91ca-4e5d-953f-be85838d3cb9"
		fingerprint = "c8374ff2a85f90f153bcd2451109a65d3757eb7cef21abef69f7c6a4f214b051"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mobidash"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mobidash"
		filetype = "executable"

	strings:
		$a = { 84 C0 75 1E 8B 44 24 2C 89 7C 24 04 89 34 24 89 44 24 0C 8B 44 }

	condition:
		all of them
}
