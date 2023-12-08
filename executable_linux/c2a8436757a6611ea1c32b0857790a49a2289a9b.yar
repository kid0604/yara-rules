rule Linux_Trojan_Ipstorm_08bcf61c
{
	meta:
		author = "Elastic Security"
		id = "08bcf61c-baef-4320-885c-8f8949684dde"
		fingerprint = "348295602b1582839f6acc603832f09e9afab71731bc21742d1a638e41df6e7c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ipstorm"
		reference_sample = "503f293d84de4f2c826f81a68180ad869e0d1448ea6c0dbf09a7b23801e1a9b9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Ipstorm with fingerprint 08bcf61c"
		filetype = "executable"

	strings:
		$a = { 8C 24 98 00 00 00 31 D2 31 DB EB 04 48 83 C1 18 48 8B 31 48 83 79 }

	condition:
		all of them
}
