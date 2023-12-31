rule win_sneepy_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.sneepy."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sneepy"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 83c40c 33c0 8a8810234100 }
		$sequence_1 = { 83f8ff 0f85abfeffff 5f 5e }
		$sequence_2 = { 8945e4 8845e8 e8???????? 8d55e4 83c404 2bd0 8a08 }
		$sequence_3 = { ffd6 85c0 740d 8b85b8feffff 50 ffd6 }
		$sequence_4 = { e8???????? 83c40c 32c0 5e 8b4dfc }
		$sequence_5 = { 68???????? 8945f4 8845f8 e8???????? 8d55f4 83c404 }
		$sequence_6 = { ff15???????? 8bc8 8a10 40 }
		$sequence_7 = { 33c0 8b4d08 3b0cc520de4000 740a 40 83f816 72ee }
		$sequence_8 = { 668b0d???????? 8a15???????? 668908 6a50 }
		$sequence_9 = { 33c0 8945e4 83f805 7d10 668b4c4310 66890c4514314100 }

	condition:
		7 of them and filesize <188416
}
