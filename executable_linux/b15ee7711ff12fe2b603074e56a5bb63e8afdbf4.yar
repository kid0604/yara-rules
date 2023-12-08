rule Linux_Trojan_Mirai_a2d2e15a
{
	meta:
		author = "Elastic Security"
		id = "a2d2e15a-a2eb-43c6-a43d-094ee9739749"
		fingerprint = "0e57d17f5c0cd876248a32d4c9cbe69b5103899af36e72e4ec3119fa48e68de2"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "567c3ce9bbbda760be81c286bfb2252418f551a64ba1189f6c0ec8ec059cee49"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant a2d2e15a"
		filetype = "executable"

	strings:
		$a = { 42 F0 41 83 F8 01 76 5F 44 0F B7 41 10 4C 01 C0 44 8D 42 EE 41 83 }

	condition:
		all of them
}
