rule win_nozelesn_decryptor_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.nozelesn_decryptor."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nozelesn_decryptor"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b459c 8d4dd8 51 8b00 8b701c 8bce e8???????? }
		$sequence_1 = { c7401000000000 c7401407000000 668908 c645fc06 8bb5ccfbffff 85f6 0f848d100000 }
		$sequence_2 = { 8bc1 83e801 747b 83e801 7466 2d0f010000 7416 }
		$sequence_3 = { 3bcf 7c10 7f07 3d???????? 7607 bf???????? eb02 }
		$sequence_4 = { 743f 8b7b0c eb28 8b4608 }
		$sequence_5 = { 8b5508 85d2 7436 8bc2 8945fc 83fa04 721f }
		$sequence_6 = { ff7730 c745fc01000000 8945a0 c645ac00 c645ad00 e8???????? 8d4584 }
		$sequence_7 = { e8???????? 837b3800 884340 7510 8b430c 8bcb 83c804 }
		$sequence_8 = { 33d7 8945e8 33d6 8bf0 c1c20d 33f1 8bc2 }
		$sequence_9 = { 7428 8b03 8d4d90 51 8b7018 8bce e8???????? }

	condition:
		7 of them and filesize <1122304
}