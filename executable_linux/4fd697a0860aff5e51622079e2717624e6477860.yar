rule Linux_Trojan_Gafgyt_27de1106
{
	meta:
		author = "Elastic Security"
		id = "27de1106-497d-40a0-8fc4-929f7a927628"
		fingerprint = "9a747f0fc7ccc55f24f2654344484f643103da709270a45de4c1174d8e4101cc"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "899c072730590003b98278bdda21c15ecaa2f49ad51e417ed59e88caf054a72d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt with ID 27de1106"
		filetype = "executable"

	strings:
		$a = { 0C 0F B6 00 84 C0 74 18 8B 45 0C 40 8B 55 08 42 89 44 24 04 89 }

	condition:
		all of them
}
