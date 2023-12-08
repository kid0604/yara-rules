rule Linux_Cryptominer_Generic_e36a35b0
{
	meta:
		author = "Elastic Security"
		id = "e36a35b0-cb38-4d2d-bca2-f3734637faa8"
		fingerprint = "0ee42ff704c82ee6c2bc0408cccb77bcbae8d4405bb1f405ee09b093e7a626c0"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "ab6d8f09df67a86fed4faabe4127cc65570dbb9ec56a1bdc484e72b72476f5a4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 71 F2 08 66 0F EF C1 66 0F EF D3 66 0F 7F 44 24 60 66 0F 7F 54 }

	condition:
		all of them
}
