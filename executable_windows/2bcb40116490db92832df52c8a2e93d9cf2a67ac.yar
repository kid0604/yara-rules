rule win_safenet_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.safenet."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.safenet"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4004 50 c3 8b442404 668b08 }
		$sequence_1 = { 50 ff15???????? 85c0 7511 6a01 5b }
		$sequence_2 = { 57 8d45e6 6a02 50 e8???????? 836d0804 83c420 }
		$sequence_3 = { 8b08 50 897920 8b4df0 83602000 e8???????? }
		$sequence_4 = { ff7008 ff7604 ff15???????? 8bcf e8???????? }
		$sequence_5 = { 8d4db8 c645fc01 e8???????? 6a01 8d4dcc 885dfc }
		$sequence_6 = { 57 ff7614 ff55f8 85c0 0f85d7000000 397df4 }
		$sequence_7 = { ffd6 83c414 8d85b0fbffff ff77f8 }
		$sequence_8 = { ff750c e8???????? ff75ec e8???????? ff75e8 e8???????? }
		$sequence_9 = { bf???????? 8b45d4 85c0 7505 b8???????? 57 50 }

	condition:
		7 of them and filesize <262144
}
