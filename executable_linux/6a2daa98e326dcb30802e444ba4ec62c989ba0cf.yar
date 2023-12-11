rule Linux_Trojan_Generic_5e981634
{
	meta:
		author = "Elastic Security"
		id = "5e981634-e34e-4943-bf8f-86cfd9fffc85"
		fingerprint = "57f1e8fa41f6577f41a73e3460ef0c6c5b0a65567ae0962b080dfc8ab18364f5"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "448e8d71e335cabf5c4e9e8d2d31e6b52f620dbf408d8cc9a6232a81c051441b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic"
		filetype = "executable"

	strings:
		$a = { 74 1D 8B 44 24 68 89 84 24 A4 00 00 00 8B 44 24 6C 89 84 24 A8 00 }

	condition:
		all of them
}
