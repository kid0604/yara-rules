rule Linux_Hacktool_Earthworm_4de7b584
{
	meta:
		author = "Elastic Security"
		id = "4de7b584-d25f-414b-bdd5-45f3672a62d8"
		fingerprint = "af2dc166ad5bbd3e312338a3932134c33c33c124551e7828eeef299d89419d21"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Earthworm"
		reference_sample = "9d61aabcf935121b4f7fc6b0d082d7d6c31cb43bf253a8603dd46435e66b7955"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Earthworm"
		filetype = "executable"

	strings:
		$a = { 73 6F 63 6B 73 64 20 2C 20 72 63 73 6F 63 6B 73 20 2C 20 72 73 }

	condition:
		all of them
}
