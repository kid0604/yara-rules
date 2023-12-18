rule win_isaacwiper_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.isaacwiper."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.isaacwiper"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 771b 52 51 e8???????? 83c408 5f c706???????? }
		$sequence_1 = { b804000000 33d2 395138 0f45c2 0b410c 0bc3 50 }
		$sequence_2 = { 8d0471 3bc8 7319 8d46ff }
		$sequence_3 = { 5b 8be5 5d c3 6a34 e8???????? 8bf0 }
		$sequence_4 = { 7576 eb56 8b0485d89e0210 6800080000 6a00 50 8945fc }
		$sequence_5 = { 744a 83c118 57 8b7d14 894d08 0f1f4000 }
		$sequence_6 = { 81ecc8090000 56 57 8bf1 c745f800000000 ff15???????? 898538f6ffff }
		$sequence_7 = { 6685f6 743e 6a00 8bd6 8bcf e8???????? 8ad0 }
		$sequence_8 = { 85db 0f8454010000 8bc6 83e001 03c8 d1ee }
		$sequence_9 = { 8bf8 83e03f c1ff06 6bd038 8b34bde8670310 8a441628 }

	condition:
		7 of them and filesize <467968
}
