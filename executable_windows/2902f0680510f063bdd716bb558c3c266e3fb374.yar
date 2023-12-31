rule win_nemty_auto_alt_2
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.nemty."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nemty"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 51 e8???????? 59 e8???????? 83c438 85c0 }
		$sequence_1 = { 8945a4 a1???????? 59 bf???????? 8bca 83f810 7302 }
		$sequence_2 = { 81ec18040000 a1???????? 33c5 8945fc 837d2010 8b4508 }
		$sequence_3 = { 83781408 8b4810 57 7202 8b00 8b3d???????? 33db }
		$sequence_4 = { 6a1c 99 5e f7fe 33db 895dd8 }
		$sequence_5 = { 33ff e8???????? 83c61c 3b7510 75ef 6a00 }
		$sequence_6 = { 83ec1c 8bd8 8bc4 68???????? e8???????? }
		$sequence_7 = { 8db4248c000000 e8???????? 53 8d742454 }
		$sequence_8 = { 7509 be???????? 85c0 7405 }
		$sequence_9 = { 837d3810 8bf8 8b4524 59 7303 8d4524 837d3810 }

	condition:
		7 of them and filesize <204800
}
