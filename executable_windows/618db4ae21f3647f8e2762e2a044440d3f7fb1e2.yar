rule win_kerrdown_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.kerrdown."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kerrdown"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 5d c20800 85f6 75b2 83ff10 8935???????? b8???????? }
		$sequence_1 = { 8bec 8b0d???????? b8???????? 8b15???????? 57 8b3d???????? 83ff10 }
		$sequence_2 = { 8aca c0e206 c0e902 80e10f 02c8 8a45eb 243f }
		$sequence_3 = { b8???????? 0f43d1 b9???????? 2bc2 50 }
		$sequence_4 = { 0f43c1 3d???????? 773e 83ff10 }
		$sequence_5 = { 83ff10 ba???????? b8???????? 0f43d1 b9???????? 2bc2 }
		$sequence_6 = { 80e10f 02c8 8a45eb 243f }
		$sequence_7 = { ff750c 83ff10 ba???????? b8???????? 0f43d1 b9???????? 2bc2 }
		$sequence_8 = { e8???????? 46 83fe03 7cec 8b4de0 }
		$sequence_9 = { 0f854d0d0000 eb00 f30f7e442404 660f2815???????? 660f28c8 }

	condition:
		7 of them and filesize <278528
}
