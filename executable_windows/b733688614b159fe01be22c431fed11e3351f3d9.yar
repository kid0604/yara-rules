rule win_winsloader_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.winsloader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.winsloader"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83c40c 6800040000 8d8dfcf7ffff 51 }
		$sequence_1 = { 8bf8 83c434 85ff 7510 }
		$sequence_2 = { 89941d02fcffff 89841d06fcffff b8???????? 898c1d0afcffff 83c410 }
		$sequence_3 = { 68???????? 51 e8???????? 68???????? 8d5c3e04 e8???????? }
		$sequence_4 = { 898c1d0afcffff 83c410 66c7841d0efcffff4501 8d7001 8a08 }
		$sequence_5 = { 8d8375050000 6a00 a3???????? ff15???????? }
		$sequence_6 = { 0fb7c0 8bf0 6689841d10fcffff 56 83c316 8d941dfcfbffff 68???????? }
		$sequence_7 = { f3a5 66a5 8b15???????? 8990fa0d0000 8b0d???????? }
		$sequence_8 = { 8bd8 c745fcffffffff 85db 7516 56 e8???????? }
		$sequence_9 = { c3 e8???????? 85c0 0f8487660000 c3 833d????????ff 7503 }
		$sequence_10 = { 894dfc 80fb08 750f 32db }
		$sequence_11 = { 33c0 40 e9???????? 8365c800 c745cc231a0110 a1???????? 8d4dc8 }
		$sequence_12 = { 8d940dfcfbffff 52 e8???????? 83c40c 0fb685f7f3ffff }
		$sequence_13 = { c1e100 8b9568f3ffff 8991a8ad0110 8b85f8f3ffff 05b4130000 668985f0f3ffff }
		$sequence_14 = { 8841ff 83ea01 75f2 8b542424 8a1a 8d4701 50 }
		$sequence_15 = { 8b049594440110 8985ccf6ffff 85c0 757c 50 8985d4f4ffff 89855cfcffff }

	condition:
		7 of them and filesize <270336
}
