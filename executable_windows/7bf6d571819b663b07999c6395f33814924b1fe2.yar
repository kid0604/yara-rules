rule Windows_Trojan_Beam_5a951d13
{
	meta:
		author = "Elastic Security"
		id = "5a951d13-9568-4a5f-bda3-645143bc16a1"
		fingerprint = "e3de6b47e563ebfd735cdd56f5b4077a8923026520ecca0628c5704272ea52bb"
		creation_date = "2021-12-07"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Beam"
		reference_sample = "233a1f1dcbb679d31dab7744358b434cccabfc752baf53ba991388ced098f7c8"
		severity = 99
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Beam"
		filetype = "executable"

	strings:
		$a1 = { 24 40 8B CE 2B C8 3B CA 0F 42 D1 83 FF 10 8D 4C 24 18 0F 43 CB }

	condition:
		all of them
}
