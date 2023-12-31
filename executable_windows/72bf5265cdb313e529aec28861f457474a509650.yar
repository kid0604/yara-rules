rule win_mgbot_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.mgbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mgbot"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 5e c20400 ff742408 ff742408 e8???????? }
		$sequence_1 = { 8be5 5d c20800 6808020000 e8???????? }
		$sequence_2 = { 6808020000 e8???????? 6804010000 8bf0 6a00 56 e8???????? }
		$sequence_3 = { 5d c20800 6808020000 e8???????? }
		$sequence_4 = { 6808020000 e8???????? 6804010000 8bf0 }
		$sequence_5 = { 5b 8be5 5d c20800 6808020000 e8???????? }
		$sequence_6 = { 5b 8be5 5d c20800 6808020000 }
		$sequence_7 = { 6808020000 e8???????? 6804010000 8bf0 6a00 }
		$sequence_8 = { 8be5 5d c20800 6808020000 }
		$sequence_9 = { 6808020000 e8???????? 6804010000 8bf0 6a00 56 }

	condition:
		7 of them and filesize <1677312
}
