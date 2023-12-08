rule Linux_Cryptominer_Generic_55beb2ee
{
	meta:
		author = "Elastic Security"
		id = "55beb2ee-7306-4134-a512-840671cc4490"
		fingerprint = "707a1478f86da2ec72580cfe4715b466e44c345deb6382b8dc3ece4e3935514d"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "edda1c6b3395e7f14dd201095c1e9303968d02c127ff9bf6c76af6b3d02e80ad"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 24 FC 00 00 00 8B 84 24 C0 00 00 00 0F 29 84 24 80 00 00 00 0F 11 94 24 C4 00 }

	condition:
		all of them
}
