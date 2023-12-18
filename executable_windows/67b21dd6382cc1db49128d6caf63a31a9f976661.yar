rule win_lowball_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.lowball."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lowball"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0f8436010000 8b942430060000 33c9 85d2 740c 8bfa }
		$sequence_1 = { ff54242c 5f 5e 5d 33c0 }
		$sequence_2 = { 8d4f01 51 e8???????? 56 8bd8 ff15???????? }
		$sequence_3 = { 68???????? f3a4 6a00 ff54242c 6810270000 ff15???????? bf???????? }
		$sequence_4 = { 85ff 897c240c 0f848c000000 8b942420020000 55 }
		$sequence_5 = { c1e902 f3a5 8bcb 8d84244c0d0000 83e103 50 }
		$sequence_6 = { 83c410 85c0 752d 68b80b0000 ffd3 8d8c24400a0000 8d94241c010000 }
		$sequence_7 = { 8bc1 8bf7 8bfa 8d942434070000 c1e902 f3a5 8bc8 }
		$sequence_8 = { ff15???????? 83c404 89442410 b905000000 be???????? }
		$sequence_9 = { 6a00 6a00 68bb010000 51 56 }

	condition:
		7 of them and filesize <40960
}
