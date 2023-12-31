rule win_mortalkombat_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.mortalkombat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mortalkombat"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 33d2 ad 3382b96d4000 ab 83c204 }
		$sequence_1 = { 6a00 6803800000 ff75fc e8???????? 83f800 7e35 6a00 }
		$sequence_2 = { 2bc1 81ebb979379e 8bc8 c1e104 }
		$sequence_3 = { 83f8ff 7402 eb67 6a00 6a00 6a02 }
		$sequence_4 = { e8???????? 50 ff75ac e8???????? 8945a4 33c0 50 }
		$sequence_5 = { 803d????????01 7519 68???????? 68???????? 68???????? }
		$sequence_6 = { c705????????f4010000 68???????? e8???????? a3???????? a0???????? }
		$sequence_7 = { ff7514 6a01 6a00 ff7510 ff75f8 }
		$sequence_8 = { 68???????? e8???????? 83c710 6a10 }
		$sequence_9 = { 50 e8???????? ebd8 8b45bc }

	condition:
		7 of them and filesize <1224704
}
