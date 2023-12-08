rule Linux_Trojan_Dropperl_39f4cd0d
{
	meta:
		author = "Elastic Security"
		id = "39f4cd0d-4261-4d62-a527-f403edadbd0c"
		fingerprint = "e1cdd678a1f46a3c6d26d53dd96ba6c6a45f97e743765c534f644af7c6450f8e"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Dropperl"
		reference_sample = "c08e1347877dc77ad73c1e017f928c69c8c78a0e3c16ac5455668d2ad22500f3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Dropperl"
		filetype = "executable"

	strings:
		$a = { E8 ?? FA FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }

	condition:
		all of them
}
