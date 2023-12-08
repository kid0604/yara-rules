rule Linux_Hacktool_Flooder_25c48456
{
	meta:
		author = "Elastic Security"
		id = "25c48456-2f83-41a8-ba37-b557014d1d86"
		fingerprint = "0c79f8eaacd2aa1fa60d5bfb7b567a9fc3e65068be1516ca723cb1394bb564ce"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "eba6f3e4f7b53e22522d82bdbdf5271c3fc701cbe07e9ecb7b4c0b85adc9d6b4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 45 F8 48 83 6D E0 01 48 83 7D E0 00 75 DD 48 8B 45 F0 C9 C3 55 48 }

	condition:
		all of them
}
