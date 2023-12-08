rule Linux_Trojan_Gafgyt_a33a8363
{
	meta:
		author = "Elastic Security"
		id = "a33a8363-5511-4fe1-a0d8-75156b9ccfc7"
		fingerprint = "74f964eaadbf8f30d40cdec40b603c5141135d2e658e7ce217d0d6c62e18dd08"
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
		$a = { 41 88 02 48 85 D2 75 ED 5A 5B 5D 41 5C 41 5D 4C 89 F0 41 5E }

	condition:
		all of them
}
