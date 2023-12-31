rule win_turian_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.turian."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.turian"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 51 e8???????? 83c404 a0???????? 84c0 }
		$sequence_1 = { 8b442410 68fc1b0000 55 50 53 6a00 }
		$sequence_2 = { bf???????? f3a5 668b15???????? 52 68???????? e8???????? 83c408 }
		$sequence_3 = { 5b 81c420040000 c3 8d442410 6a10 50 8bce }
		$sequence_4 = { 68???????? 6886000000 51 68???????? 68???????? ff15???????? }
		$sequence_5 = { 6a00 25ffff0000 6a00 68fc1b0000 d1e8 53 }
		$sequence_6 = { 75bc 8b542414 52 ffd5 5f 5e 33c0 }
		$sequence_7 = { 68???????? ff15???????? a1???????? 83f864 }
		$sequence_8 = { 8d740704 ffd5 3206 32c3 8806 8b442410 }
		$sequence_9 = { 50 ffd7 56 ff15???????? 83c404 33c0 }

	condition:
		7 of them and filesize <645120
}
