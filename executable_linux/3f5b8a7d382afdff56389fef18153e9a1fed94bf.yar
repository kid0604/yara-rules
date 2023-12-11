rule Linux_Trojan_Tsunami_9ce5b69f
{
	meta:
		author = "Elastic Security"
		id = "9ce5b69f-4938-4576-89da-8dcd492708ed"
		fingerprint = "90fece6c2950467d78c8a9f1d72054adf854f19cdb33e71db0234a7b0aebef47"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "ad63fbd15b7de4da0db1b38609b7481253c100e3028c19831a5d5c1926351829"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { F4 8B 54 85 B4 8B 45 E4 8D 04 02 C6 00 00 FF 45 F4 8B 45 E4 01 }

	condition:
		all of them
}
