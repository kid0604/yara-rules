rule win_yayih_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.yayih."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yayih"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 2b7d0c 75df 6a01 58 5f 5e }
		$sequence_1 = { 61 ff45c8 817dc8c4090000 0f8dbe0c0000 }
		$sequence_2 = { 6a04 ebb8 ff35???????? ff15???????? }
		$sequence_3 = { 56 6a04 ebb8 ff35???????? }
		$sequence_4 = { 83c001 41 49 90 }
		$sequence_5 = { e8???????? ff750c e8???????? 59 40 50 }
		$sequence_6 = { ff15???????? 8d85b8b8ffff 50 56 ff75d4 56 }
		$sequence_7 = { 8d4580 50 68???????? e8???????? 59 59 50 }
		$sequence_8 = { 50 e8???????? 83c430 8d459c 50 8d8518ffffff }
		$sequence_9 = { ff15???????? ff35???????? ff15???????? 8d85b8b8ffff 68???????? }

	condition:
		7 of them and filesize <57344
}
