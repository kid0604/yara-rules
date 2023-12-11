rule Linux_Cryptominer_Flystudio_0a370634
{
	meta:
		author = "Elastic Security"
		id = "0a370634-51de-46bf-9397-c41ef08a7b83"
		fingerprint = "6613ddd986e2bf4b306cd1a5c28952da8068f1bb533c53557e2e2add5c2dbd1f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Flystudio"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Flystudio malware"
		filetype = "executable"

	strings:
		$a = { 72 D7 19 66 41 0F EF E9 66 0F EF EF 66 0F 6F FD 66 41 0F FE FD 66 44 0F }

	condition:
		all of them
}
