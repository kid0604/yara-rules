rule win_badflick_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.badflick."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.badflick"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b07 83f8ff 741c 3b450c 7f17 }
		$sequence_1 = { 84c0 7516 ff7514 ff35???????? 57 e8???????? }
		$sequence_2 = { ff75fc 8907 e8???????? 59 32c0 5f }
		$sequence_3 = { ff15???????? 8bd8 83fbff 746b 56 }
		$sequence_4 = { 8d44000a 50 6a41 e8???????? ff750c 8bf0 8d460d }
		$sequence_5 = { 57 e8???????? 8bd8 59 59 85db 0f841b020000 }
		$sequence_6 = { 8b4315 8945e0 8b4319 8945e4 8d4321 50 }
		$sequence_7 = { e8???????? 8bf0 56 e8???????? 56 8bf8 ff15???????? }
		$sequence_8 = { 83c410 8d45e0 50 eb01 53 ffd6 }
		$sequence_9 = { 8d85ecfbffff ff35???????? 68???????? ff35???????? }

	condition:
		7 of them and filesize <81920
}
