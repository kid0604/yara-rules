rule MacOS_Trojan_Bundlore_3965578d
{
	meta:
		author = "Elastic Security"
		id = "3965578d-3180-48e4-b5be-532e880b1df9"
		fingerprint = "e41f08618db822ba5185e5dc3f932a72e1070fbb424ff2c097cab5e58ad9e2db"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Bundlore"
		reference_sample = "d72543505e36db40e0ccbf14f4ce3853b1022a8aeadd96d173d84e068b4f68fa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Trojan.Bundlore malware"
		filetype = "executable"

	strings:
		$a = { 35 33 2A 00 00 60 80 35 2D 2A 00 00 D0 80 35 27 2A 00 00 54 80 35 21 2A 00 00 }

	condition:
		all of them
}
