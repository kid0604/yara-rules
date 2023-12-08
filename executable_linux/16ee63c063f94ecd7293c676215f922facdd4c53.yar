rule Linux_Cryptominer_Xmrminer_2dd045fc
{
	meta:
		author = "Elastic Security"
		id = "2dd045fc-a585-4a49-b334-773bc86a3370"
		fingerprint = "b5f02ac76db686e61c6f293183f2c17fe0f901a65eebaccfe109f07fc9abeeaa"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrminer"
		reference_sample = "30a77ab582f0558829a78960929f657a7c3c03c2cf89cd5a0f6934b79a74b7a4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrminer malware"
		filetype = "executable"

	strings:
		$a = { BA 0E 00 00 00 74 25 48 8B 8C 24 B8 00 00 00 64 48 33 0C 25 28 00 }

	condition:
		all of them
}
