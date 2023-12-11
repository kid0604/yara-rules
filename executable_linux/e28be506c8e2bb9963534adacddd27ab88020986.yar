rule Linux_Trojan_Tsunami_36a98405
{
	meta:
		author = "Elastic Security"
		id = "36a98405-8b95-49cb-98c5-df4a445d9d39"
		fingerprint = "c76ca23eece4c2d4ec6656ffb40d6e6ea7777d8a904f4775913fe60ebd606cd6"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "a57de6cd3468f55b4bfded5f1eed610fdb2cbffbb584660ae000c20663d5b304"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 05 88 85 50 FF FF FF 0F B6 85 50 FF FF FF 83 E0 0F 83 C8 40 88 85 50 FF }

	condition:
		all of them
}
