rule Linux_Trojan_Mobidash_52a15a93
{
	meta:
		author = "Elastic Security"
		id = "52a15a93-0574-44bb-83c9-793558432553"
		fingerprint = "a7ceff3bbd61929ab000d18ffdf2e8d1753ecea123e26cd626e3af64341effe6"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mobidash"
		reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Mobidash"
		filetype = "executable"

	strings:
		$a = { 41 89 CE 41 55 41 54 49 89 F4 55 48 89 D5 53 48 89 FB 48 8B 07 FF 90 F8 00 }

	condition:
		all of them
}
