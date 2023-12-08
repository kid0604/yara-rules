rule Linux_Trojan_Gafgyt_821173df
{
	meta:
		author = "Elastic Security"
		id = "821173df-6835-41e1-a662-a432abf23431"
		fingerprint = "c311789e1370227f7be1d87da0c370a905b7f5b4c55cdee0f0474060cc0fc5e4"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "de7d1aff222c7d474e1a42b2368885ef16317e8da1ca3a63009bf06376026163"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { D0 48 FF C8 48 03 45 F8 48 FF C8 C6 00 00 48 8B 45 F8 48 C7 C1 FF FF }

	condition:
		all of them
}
