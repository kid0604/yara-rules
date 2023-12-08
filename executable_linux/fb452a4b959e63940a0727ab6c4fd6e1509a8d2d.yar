rule Linux_Trojan_Mirai_564b8eda
{
	meta:
		author = "Elastic Security"
		id = "564b8eda-6f0e-45b8-bef6-d61b0f090a36"
		fingerprint = "63a9e43902e7db0b7a20498b5a860e36201bacc407e9e336faca0b7cfbc37819"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "ff04921d7bf9ca01ae33a9fc0743dce9ca250e42a33547c5665b1c9a0b5260ee"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 83 FE 01 76 12 0F B7 07 83 EE 02 48 83 C7 02 48 01 C1 83 FE 01 }

	condition:
		all of them
}
