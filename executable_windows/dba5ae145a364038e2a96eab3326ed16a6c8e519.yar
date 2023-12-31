rule win_crypto_fortress_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.crypto_fortress."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crypto_fortress"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ffb5a8feffff e8???????? 68???????? ffb5a8feffff e8???????? }
		$sequence_1 = { a3???????? 68???????? ff35???????? e8???????? 85c0 0f846f030000 }
		$sequence_2 = { aa 3407 aa 045a aa }
		$sequence_3 = { e8???????? 85c0 0f846f030000 a3???????? 68???????? ff35???????? e8???????? }
		$sequence_4 = { ff35???????? e8???????? 85c0 0f8456060000 a3???????? 8d3dccec4000 33c0 }
		$sequence_5 = { 2cff aa 2cf9 aa 2c4c }
		$sequence_6 = { aa 2c4e aa 0444 aa 2cff aa }
		$sequence_7 = { c9 c20800 55 8bec 83c4f8 8b4508 }
		$sequence_8 = { aa 341b aa 2c27 aa 3441 aa }
		$sequence_9 = { aa 340a aa 3421 aa 0433 aa }

	condition:
		7 of them and filesize <188416
}
