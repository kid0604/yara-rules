rule win_urausy_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.urausy."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.urausy"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a00 68???????? 68???????? ff7508 e8???????? 6a00 ff35???????? }
		$sequence_1 = { 8bd3 81c2a5000000 50 53 52 51 }
		$sequence_2 = { ff75e4 e8???????? 8945e8 ff35???????? }
		$sequence_3 = { 6a01 ff35???????? e8???????? 6a00 68???????? 68???????? }
		$sequence_4 = { c21000 55 8bec 81c4ecefffff }
		$sequence_5 = { 0f8585000000 6814000000 68???????? 6a04 8d8500fcffff 50 e8???????? }
		$sequence_6 = { 8d85dcf7ffff 50 57 56 }
		$sequence_7 = { 833d????????00 0f8fae050000 c705????????01000000 ff35???????? 8f45f0 ff35???????? 8f45f4 }
		$sequence_8 = { e8???????? ff75fc e8???????? 8b45f8 c9 c20400 ff25???????? }
		$sequence_9 = { e8???????? b800000000 c9 c21400 }

	condition:
		7 of them and filesize <98304
}
