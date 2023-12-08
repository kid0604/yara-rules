rule win_lowkey_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.lowkey."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lowkey"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff5020 66837c247001 488d05bb0e0200 448b4dd8 488d5500 480f45442478 488d4d30 }
		$sequence_1 = { 488d5510 40887c0510 897c2458 48897c2420 ff15???????? 85c0 }
		$sequence_2 = { 3939 0f85b3040000 4c89ac24a8470000 458d6e66 660f1f440000 41b910000000 }
		$sequence_3 = { 488d057c4a0100 48c74424580e000000 4889442450 488d4c2470 4883c8ff 48ffc0 66391c41 }
		$sequence_4 = { 668945ad 488d55a8 e8???????? 85c0 0f95c3 8bc3 488b8d30400000 }
		$sequence_5 = { 4833cc e8???????? 4c8d9c24a0210000 498b5b20 498b7330 }
		$sequence_6 = { 3c09 7769 48ffc1 488d040a 493bc0 7ce7 488bcb }
		$sequence_7 = { 4883c420 5d c3 488b8a50000000 4883c128 e9???????? }
		$sequence_8 = { 4533c9 4889742428 4533c0 33d2 89742430 488b4f10 4889442420 }
		$sequence_9 = { c6435401 488d0d4f1e0100 480f45cf 48894b48 e8???????? eb17 4885ff }

	condition:
		7 of them and filesize <643072
}
