rule win_hookinjex_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.hookinjex."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hookinjex"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 85c0 740c b913e40000 }
		$sequence_1 = { e8???????? b964000000 ff15???????? 0fb705???????? }
		$sequence_2 = { e8???????? 85c0 7507 b80e000000 }
		$sequence_3 = { e9???????? 488b4c2458 e8???????? 488b4c2450 }
		$sequence_4 = { e8???????? b95b730100 e8???????? e9???????? }
		$sequence_5 = { e8???????? 85c0 750f b9dc550100 }
		$sequence_6 = { e8???????? 833d????????00 7411 b903000000 e8???????? }
		$sequence_7 = { e8???????? 85c0 7408 803b00 }
		$sequence_8 = { 48817c243000100000 0f82dc020000 488b442460 4889442438 }
		$sequence_9 = { 2500180000 3d00080000 750d c78424e800000001000000 eb0b }
		$sequence_10 = { 25001b0000 3d00100000 750a c744244401000000 }
		$sequence_11 = { 25001b0000 3d00110000 750d c784243c01000001000000 }
		$sequence_12 = { 25001b0000 3d00100000 750d c784242401000001000000 }
		$sequence_13 = { 2500180000 3d00180000 750a c744247c01000000 }
		$sequence_14 = { 25001b0000 3d00110000 750a c744245c01000000 }
		$sequence_15 = { 48817c243800100000 0f82f5000000 488b442438 4883c02f }

	condition:
		7 of them and filesize <6545408
}