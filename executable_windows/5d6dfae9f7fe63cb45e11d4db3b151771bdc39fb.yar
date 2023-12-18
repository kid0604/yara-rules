rule win_maoloa_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.maoloa."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maoloa"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b55fc 8bcb 85c0 7817 8d45f0 50 e8???????? }
		$sequence_1 = { 50 ffb5f0e4ffff 8b35???????? ffd6 8b85c0e4ffff c1e015 03858ce5ffff }
		$sequence_2 = { 8b4df8 33cd e8???????? 8be5 5d c3 befcffffff }
		$sequence_3 = { 83c404 85f6 0f8590000000 6a01 8bd7 8bcf e8???????? }
		$sequence_4 = { 85c0 8d8d00e0ffff 0f45ce 8bf1 89b5f8dfffff 8d85f8efffff 50 }
		$sequence_5 = { b910000000 0f43c1 8d4c2418 2bf8 }
		$sequence_6 = { 8d97a9cfde4b 33c1 894db4 0345d0 03d0 8b7db4 c1c20b }
		$sequence_7 = { 8bd3 c707ffffffff 8bcf e8???????? 83c404 8bf0 8b85e0f9ffff }
		$sequence_8 = { 0f1f00 0fb601 8d4901 30440eff 0fb641ff 30440aff 83ef01 }
		$sequence_9 = { 5e 5b 8be5 5d c3 8d45f0 8bd1 }

	condition:
		7 of them and filesize <586752
}
