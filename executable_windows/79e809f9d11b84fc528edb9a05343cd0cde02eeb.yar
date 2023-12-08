rule win_safenet_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.safenet."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.safenet"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 81ff???????? 0f8234ffffff e8???????? 85c0 }
		$sequence_1 = { 85c0 7c03 6a01 5e ff15???????? e8???????? }
		$sequence_2 = { e8???????? 8b45b0 53 89854cffffff 8b45b4 }
		$sequence_3 = { 50 e8???????? 53 e8???????? 8b45f0 59 }
		$sequence_4 = { 50 ffd6 83c414 8d85f8fdffff ff77fc 50 }
		$sequence_5 = { 3db7000000 7407 ffd6 e9???????? 8d45f8 33db 50 }
		$sequence_6 = { ff750c ff7508 50 ff7604 ff15???????? 85c0 7439 }
		$sequence_7 = { b8???????? 57 50 e8???????? 59 85c0 }
		$sequence_8 = { 8d430c 50 e8???????? 53 e8???????? 8b45f0 59 }
		$sequence_9 = { 56 ff75f0 ff15???????? 8bf8 3bfe 7429 }

	condition:
		7 of them and filesize <262144
}
