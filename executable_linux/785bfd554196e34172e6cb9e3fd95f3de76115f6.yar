rule Linux_Trojan_Gafgyt_eaa9a668
{
	meta:
		author = "Elastic Security"
		id = "eaa9a668-e3b9-4657-81bf-1c6456e2053a"
		fingerprint = "bee2744457164e5747575a101026c7862474154d82f52151ac0d77fb278d9405"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Trojan.Gafgyt malware"
		filetype = "executable"

	strings:
		$a = { 45 C0 0F B6 00 3C 2F 76 0B 48 8B 45 C0 0F B6 00 3C 39 76 C7 48 8B }

	condition:
		all of them
}
