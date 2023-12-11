rule Linux_Hacktool_Flooder_30973084
{
	meta:
		author = "Elastic Security"
		id = "30973084-60d2-494d-a3c6-2a015a9459a0"
		fingerprint = "44fc236199ccf53107f1a617ac872f51d58a99ec242fe97b913e55b3ec9638e2"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "a22ffa748bcaaed801f48f38b26a9cfdd5e62183a9f6f31c8a1d4a8443bf62a4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 4C 69 73 74 20 49 6D 70 6F 72 74 20 46 6F 72 20 53 6F 75 72 63 }

	condition:
		all of them
}
