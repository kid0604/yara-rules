rule Linux_Trojan_Xorddos_e3ffbbcc
{
	meta:
		author = "Elastic Security"
		id = "e3ffbbcc-7751-4d96-abec-22dd9618cab1"
		fingerprint = "d5d5117a31da1a0ac3ef4043092eed47e2844938da9d03e2b68a66658e300175"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "28b7ddf2548411910af033b41982cdc74efd8a6ef059a54fda1b6cbd59faa8f6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { FF 10 52 FB FF D0 52 FB FF 00 52 FB FF D0 52 FB FF F0 51 FB }

	condition:
		all of them
}
