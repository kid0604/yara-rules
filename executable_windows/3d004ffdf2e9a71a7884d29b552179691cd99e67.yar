rule win_bohmini_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.bohmini."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bohmini"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 896c2410 896c2414 0f86c5000000 8b7c2420 }
		$sequence_1 = { 6a00 6a00 8bca 83c11a 51 6a00 6a00 }
		$sequence_2 = { 8d542414 6a00 52 ff15???????? 85c0 }
		$sequence_3 = { ff15???????? 3bc3 a3???????? 7512 5f 5e }
		$sequence_4 = { 6800040000 50 53 ff15???????? 50 ff15???????? }
		$sequence_5 = { 4a 741a 4a 7543 e8???????? 03c6 33d2 }
		$sequence_6 = { 83c410 85c0 7507 6891130000 eb2a }
		$sequence_7 = { 8b5608 52 ffd5 40 50 }
		$sequence_8 = { 52 e8???????? 40 50 8d8424b8010000 50 }
		$sequence_9 = { 8b2d???????? 8b3e 51 6a00 ffd5 50 ffd3 }

	condition:
		7 of them and filesize <139264
}
