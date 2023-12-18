rule win_upatre_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.upatre."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.upatre"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 66ab 33c0 66ab bbff0f0000 8b75f0 }
		$sequence_1 = { 8945fc 8bd8 03c1 8bf8 33c0 }
		$sequence_2 = { 894d90 8b4d8c 85c9 7501 c3 57 }
		$sequence_3 = { 7414 4e 56 ff75f0 }
		$sequence_4 = { 0430 66ab 81c60e010000 ac }
		$sequence_5 = { 8945ec 6a00 8d4dc0 51 ff75e0 ff75bc ff75ec }
		$sequence_6 = { 895d98 8bfb 03d8 b91c010000 }
		$sequence_7 = { b900100000 03c1 8945f0 03c1 }
		$sequence_8 = { 83c008 8945bc 8b4dbc 8b5104 52 }
		$sequence_9 = { 8b55d4 8b440a1c 8945f4 8b4df0 }
		$sequence_10 = { 0f94c0 85c0 7436 8b4dd8 83c102 2b4de8 }
		$sequence_11 = { e3c9 1bb6aeaca844 bbcdcc70e8 739c d4ef }
		$sequence_12 = { eb2b 8b4df4 8b510c 52 e8???????? 83c404 0fb7c0 }
		$sequence_13 = { 8b4508 0345f0 0fbe08 8b5510 0faf55f8 0faf55f0 33ca }
		$sequence_14 = { 8945dc 8b4ddc 668b11 668955f0 0fb745f0 }
		$sequence_15 = { 894df4 8b55f4 3b550c 7d28 }

	condition:
		7 of them and filesize <294912
}
