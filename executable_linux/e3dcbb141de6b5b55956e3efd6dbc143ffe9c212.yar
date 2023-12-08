rule Linux_Trojan_Mirai_b9a9d04b
{
	meta:
		author = "Elastic Security"
		id = "b9a9d04b-a997-46c4-b893-e89a3813efd3"
		fingerprint = "874249d8ad391be97466c0259ae020cc0564788a6770bb0f07dd0653721f48b1"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint b9a9d04b"
		filetype = "executable"

	strings:
		$a = "nexuszetaisacrackaddict"

	condition:
		all of them
}
