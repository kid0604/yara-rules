rule win_rekoobew_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.rekoobew."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rekoobew"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c1e208 09d1 338b04010000 894de0 0fb67004 c1e618 0fb65005 }
		$sequence_1 = { 83c005 890424 e8???????? 8b45c4 890424 e8???????? 8d45d4 }
		$sequence_2 = { 894dd8 8d8408a1ebd96e 8945f0 89d0 31f8 31f0 0345f0 }
		$sequence_3 = { c1e918 33348de0844000 89d9 c1e910 0fb6c9 }
		$sequence_4 = { e8???????? 8d45e4 89442408 c7442404???????? 891c24 e8???????? 89c2 }
		$sequence_5 = { 8d45bc 89442408 89742404 c70424???????? e8???????? 8d45e4 89442408 }
		$sequence_6 = { 8b4de8 0fb6f5 8b4dec 330cb5e0784000 0fb675e8 8b34b5e07c4000 33b390010000 }
		$sequence_7 = { 89c2 31fa 31ca 0355f0 89de }
		$sequence_8 = { 56 53 81ecb4000000 e8???????? c70424???????? e8???????? a3???????? }
		$sequence_9 = { e8???????? 83f801 741f c744240402000000 a1???????? 890424 }

	condition:
		7 of them and filesize <248832
}
