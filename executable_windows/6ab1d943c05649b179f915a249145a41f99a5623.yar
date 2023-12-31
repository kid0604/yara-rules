rule win_blackcat_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.blackcat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackcat"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c3 894608 c7460400000000 b001 ebe8 89c2 }
		$sequence_1 = { 7260 8b06 01d8 51 57 50 89cf }
		$sequence_2 = { 8975dc 8955e0 eb07 31c0 b902000000 }
		$sequence_3 = { b104 eb0f e8???????? 89c2 c1e018 31c9 }
		$sequence_4 = { 7504 3c02 7351 88c4 8975cc }
		$sequence_5 = { 81f9cf040000 0f8fe4000000 81f96b040000 0f84b4010000 81f976040000 }
		$sequence_6 = { 83ec08 a1???????? c745f800000000 c745fc00000000 85c0 7408 8d4df8 }
		$sequence_7 = { 8d45f8 50 e8???????? 8b45f8 8b55fc 83c408 }
		$sequence_8 = { 895804 897008 eb0b 8b45e8 894708 }
		$sequence_9 = { ff45e4 8a02 42 8955e8 }

	condition:
		7 of them and filesize <29981696
}
