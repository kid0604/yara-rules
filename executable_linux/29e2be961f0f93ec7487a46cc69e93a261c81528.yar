rule Linux_Trojan_Roopre_b6b9e71d
{
	meta:
		author = "Elastic Security"
		id = "b6b9e71d-7f1c-4827-b659-f9dad5667d69"
		fingerprint = "1a87cccd06b99e0375ffef17d4b3c5fd8957013ab8de7507e9b8d1174573a6cf"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Roopre"
		reference_sample = "36ae2bf773135fdb0ead7fbbd46f90fd41d6f973569de1941c8723158fc6cfcc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Roopre"
		filetype = "executable"

	strings:
		$a = { 54 24 08 48 C7 C6 18 FC FF FF 49 8B 4A 08 48 89 C8 48 99 48 }

	condition:
		all of them
}
