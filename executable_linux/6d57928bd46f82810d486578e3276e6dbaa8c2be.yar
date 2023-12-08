rule Linux_Trojan_Gafgyt_a10161ce
{
	meta:
		author = "Elastic Security"
		id = "a10161ce-62e0-4f60-9de7-bd8caf8618be"
		fingerprint = "77e89011a67a539954358118d41ad3dabde0e69bac2bbb2b2da18eaad427d935"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 45 B0 8B 45 BC 48 63 D0 48 89 D0 48 C1 E0 02 48 8D 14 10 48 8B }

	condition:
		all of them
}
