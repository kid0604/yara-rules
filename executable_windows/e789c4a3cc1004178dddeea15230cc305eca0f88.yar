rule win_sobig_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.sobig."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sobig"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 50 e8???????? ff35???????? 8d45dc 8bcf 6a00 50 }
		$sequence_1 = { 53 50 ff75ec ff75d8 ff75dc ff15???????? 85c0 }
		$sequence_2 = { 8a450f 33db 8d7e34 53 8bcf }
		$sequence_3 = { 5f 5e c20400 53 56 ff742410 8bf1 }
		$sequence_4 = { e8???????? dd4598 8b4de8 dd5db0 dd45a0 dd5db8 dd45a8 }
		$sequence_5 = { 8d45b4 50 56 56 68???????? 56 56 }
		$sequence_6 = { 8d4db0 e8???????? 8a45b0 83ec10 8bfc 8965e0 53 }
		$sequence_7 = { 8b4d08 68???????? e8???????? 6a01 58 8945ec e9???????? }
		$sequence_8 = { ff35???????? 8d45dc 8bcf 53 }
		$sequence_9 = { ff7508 ff15???????? 85c0 7c43 ff7510 ff15???????? }

	condition:
		7 of them and filesize <262144
}
