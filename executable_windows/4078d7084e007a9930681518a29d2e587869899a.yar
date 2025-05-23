rule win_rhysida_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.rhysida."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rhysida"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 4c21f8 488903 4c89d8 4c0face03c 4889c3 4c89d0 4d8b28 }
		$sequence_1 = { 8b45f0 0145fc 8b45fc 3b45f4 7cbb 8b45f4 83c002 }
		$sequence_2 = { 85c0 8944242c 0f8582000000 488b4c2438 ff5720 8b44242c 4883c440 }
		$sequence_3 = { f30f1045d4 f30f1145d0 f30f1045d0 f30f1145cc 90 488d55cc 488d45d8 }
		$sequence_4 = { 85c0 740c c7452c00000000 e9???????? 488b4500 8b4014 85c0 }
		$sequence_5 = { 8b5010 8b45dc 01d0 f30f2ac0 f30f594514 f30f58450c 488b45f8 }
		$sequence_6 = { 4883c002 4889c1 e8???????? 668945f4 488b4510 4883c004 488945e8 }
		$sequence_7 = { e8???????? b801000000 4881c4a0110000 5d c3 55 57 }
		$sequence_8 = { 4801d1 4801d0 41d1e9 660f6f01 458d51ff ba10000000 0f1100 }
		$sequence_9 = { 85c0 75ca 4889ea 4889d9 e8???????? 83c001 7448 }

	condition:
		7 of them and filesize <2369536
}
