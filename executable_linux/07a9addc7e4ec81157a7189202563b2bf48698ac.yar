rule Linux_Exploit_Lotoor_f4afd230
{
	meta:
		author = "Elastic Security"
		id = "f4afd230-6c9f-49e8-8f13-429635b38eb5"
		fingerprint = "1709244fdc1e2d9d7fba01743b0cf87de7b940d2b25a0016e021b7e9696525bc"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "805e900ffc9edb9f550dcbc938a3b06d28e9e7d3fb604ff68a311a0accbcd2b1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { 83 20 FF FF FF 85 C0 74 25 8B 83 F8 FF FF FF 85 C0 74 1B 83 }

	condition:
		all of them
}
