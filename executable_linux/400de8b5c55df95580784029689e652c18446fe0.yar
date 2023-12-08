rule Linux_Hacktool_Flooder_ab561a1b
{
	meta:
		author = "Elastic Security"
		id = "ab561a1b-d8dd-4768-9b4c-07ef4777b252"
		fingerprint = "081dd5eb061c8023756e413420241e20a2c86097f95859181ca5d6b1d24fdd76"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "1b7df0d491974bead05d04ede6cf763ecac30ecff4d27bb4097c90cc9c3f4155"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { B5 50 FF FF FF 64 48 8B 04 25 28 00 00 00 48 89 45 C8 31 C0 83 BD 5C FF FF }

	condition:
		all of them
}
