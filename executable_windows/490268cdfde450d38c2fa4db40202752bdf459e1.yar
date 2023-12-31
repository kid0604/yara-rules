rule win_mailto_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.mailto."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mailto"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? ff742420 e8???????? 56 e8???????? 55 e8???????? }
		$sequence_1 = { 46 8bc4 89742428 0f10442420 8b11 51 }
		$sequence_2 = { 8d4810 0fb744240c 50 ff742414 8b01 56 }
		$sequence_3 = { 57 e8???????? 83c408 85c0 0f84b6010000 e8???????? 8b4010 }
		$sequence_4 = { 8bf2 8b4338 f76b40 03c8 13f2 0fa4ce01 89757c }
		$sequence_5 = { 8b442424 03c1 89442424 8bc8 8b742424 }
		$sequence_6 = { 75f8 2bcb d1f9 41 03c1 57 50 }
		$sequence_7 = { 8d4f1f 3bf8 771f 3bce 721b 8bcf 2bf7 }
		$sequence_8 = { 85f6 745f 681b040a7a 56 e8???????? 8b0d???????? 6850b21d58 }
		$sequence_9 = { eb64 83ff01 7522 0fb6d1 bf02000000 83e203 0fb6cb }

	condition:
		7 of them and filesize <180224
}
