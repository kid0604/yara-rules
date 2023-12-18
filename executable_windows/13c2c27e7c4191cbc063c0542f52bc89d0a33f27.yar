rule win_heyoka_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.heyoka."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.heyoka"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4d0c 8b510c 83c204 52 8b45fc 50 }
		$sequence_1 = { c745f800000000 c745f000000000 c745f400000000 c745ec00000000 8b4514 6bc005 c1e803 }
		$sequence_2 = { 8b45dc 50 e8???????? 83c410 8945d8 837dd800 750c }
		$sequence_3 = { 83ec08 894df8 8b45f8 c700???????? 8b4df8 c7810c09000000000000 8b55f8 }
		$sequence_4 = { e8???????? 83c408 8b5518 52 8b45dc 83c004 }
		$sequence_5 = { e8???????? 83c408 eb17 837d0803 7511 68???????? }
		$sequence_6 = { 8bec 83ec08 8b4508 50 6a01 e8???????? 83c408 }
		$sequence_7 = { 7423 8bce 8bc6 c1f905 83e01f 8b0c8da0d80110 }
		$sequence_8 = { 51 e8???????? 83c404 8b45e0 83c00c 8be5 }
		$sequence_9 = { 8955f8 8b45fc 8b4df4 8b55f8 0faf948134e30000 8b4df4 8bc2 }

	condition:
		7 of them and filesize <270336
}
