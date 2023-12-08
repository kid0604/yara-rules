rule Linux_Trojan_Gafgyt_9127f7be
{
	meta:
		author = "Elastic Security"
		id = "9127f7be-6e82-46a1-9f11-0b3570b0cd76"
		fingerprint = "72c742cb8b11ddf030e10f67e13c0392748dcd970394ec77ace3d2baa705a375"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant 9127f7be"
		filetype = "executable"

	strings:
		$a = { E4 F7 E1 89 D0 C1 E8 03 89 45 E8 8B 45 E8 01 C0 03 45 E8 C1 }

	condition:
		all of them
}
