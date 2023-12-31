rule win_dircrypt_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.dircrypt."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dircrypt"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7531 c705????????01000000 e8???????? e8???????? 833d????????00 7514 68???????? }
		$sequence_1 = { e8???????? e8???????? 68???????? ff15???????? 833d????????00 751a }
		$sequence_2 = { 68???????? e8???????? 05d2070000 50 e8???????? a3???????? 6a13 }
		$sequence_3 = { 8bec 51 6a00 6a00 8d45fc 50 68???????? }
		$sequence_4 = { 68???????? 8d45dc 50 e8???????? 6a00 e8???????? }
		$sequence_5 = { 6801000080 e8???????? e8???????? e8???????? e8???????? }
		$sequence_6 = { e8???????? 05d5070000 50 6a01 6a02 6a08 }
		$sequence_7 = { 68???????? 8d45dc 50 e8???????? 6a00 e8???????? 05d6070000 }
		$sequence_8 = { 833d????????00 7514 68???????? 68???????? e8???????? a3???????? 833d????????00 }
		$sequence_9 = { 51 6a00 6a00 8d45fc 50 68???????? 6802000080 }

	condition:
		7 of them and filesize <671744
}
