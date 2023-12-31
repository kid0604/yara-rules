rule win_matsnu_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.matsnu."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matsnu"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e9???????? 8985bcfbffff 83bdb0fbffff01 0f8588000000 8b85bcfbffff 8985c4fbffff 8b85c0fbffff }
		$sequence_1 = { eb04 c647023d 837d1003 7213 }
		$sequence_2 = { eb04 c647023d 837d1003 7213 31c0 8a4602 243f }
		$sequence_3 = { 8b45e0 3b450c 0f8391000000 c745e800000000 }
		$sequence_4 = { 750f c785a4fbffff02000000 e9???????? 8985bcfbffff 83bdb0fbffff01 0f8588000000 8b85bcfbffff }
		$sequence_5 = { 85c0 0f84a6000000 8945fc 8b45e0 3b450c }
		$sequence_6 = { c78570f3ffff00000000 c78574f3ffff00000000 c78578f3ffff00000000 c7857cf3ffff00000000 }
		$sequence_7 = { 751d ff45da ba00000000 8b45da }
		$sequence_8 = { 3b45ba 7228 8b7d08 8b4704 3b45ba 751d }
		$sequence_9 = { 89e5 81ec18020000 c785e8fdffff00000000 c785ecfdffff00000000 c785f0fdffff00000000 }

	condition:
		7 of them and filesize <606992
}
