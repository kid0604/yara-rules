rule Linux_Trojan_Dropperl_8bca73f6
{
	meta:
		author = "Elastic Security"
		id = "8bca73f6-c3ec-45a3-a5ae-67c871aaf9df"
		fingerprint = "36df2fd9746da80697ef675f84f47efb3cb90e9757677e4f565a7576966eb169"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Dropperl"
		reference_sample = "e7c17b7916b38494b9a07c249acb99499808959ba67125c29afec194ca4ae36c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Dropperl"
		filetype = "executable"

	strings:
		$a = { E8 95 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 62 00 }

	condition:
		all of them
}
