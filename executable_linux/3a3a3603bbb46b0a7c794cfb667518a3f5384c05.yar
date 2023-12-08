rule Linux_Hacktool_Flooder_8b63ff02
{
	meta:
		author = "Elastic Security"
		id = "8b63ff02-be86-4c63-8f7b-4c70fbd8a83a"
		fingerprint = "af7a4df7e707c1b70fb2b29efe2492e6f77cdde5e8d1e6bfdf141acabc8759eb"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "a57de6cd3468f55b4bfded5f1eed610fdb2cbffbb584660ae000c20663d5b304"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { DC 02 83 7D DC 01 0F 9F C0 84 C0 75 DF 83 7D DC 01 75 1D 66 C7 45 F6 }

	condition:
		all of them
}
