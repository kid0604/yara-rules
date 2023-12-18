rule win_roopirs_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.roopirs."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.roopirs"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c745fc47000000 8b4dd8 51 68???????? ff15???????? 8945c0 }
		$sequence_1 = { 50 ff15???????? 898530ffffff eb0a c78530ffffff00000000 33c9 837da800 }
		$sequence_2 = { ff15???????? 8d4db0 ff15???????? c745fc07000000 833d????????00 751c 68???????? }
		$sequence_3 = { 8945b0 837db000 7d1d 6a20 68???????? 8b45dc 50 }
		$sequence_4 = { 8d55d4 52 6a05 ff15???????? 83c418 8d45bc 50 }
		$sequence_5 = { 8b02 8b4d80 51 ff5014 dbe2 89857cffffff }
		$sequence_6 = { 8b4508 50 8b08 ff5104 8b5514 56 8d45bc }
		$sequence_7 = { c78544ffffff00000000 8b45ac 89458c 8d4dcc 51 8b558c }
		$sequence_8 = { 68???????? 68???????? ff15???????? c78548ffffffd4624000 eb0a }
		$sequence_9 = { 8d4dc8 ff15???????? c745fc07000000 8b4dd8 51 68???????? }

	condition:
		7 of them and filesize <344064
}
