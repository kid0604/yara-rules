rule win_doublepulsar_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.doublepulsar."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doublepulsar"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 731b 8a44144d 8d7c244c 8844144c }
		$sequence_1 = { 8d41ff 85c0 7c10 8a1430 80fa5c 7408 }
		$sequence_2 = { 8bc1 8bf7 8bfa 89ac245c020000 c1e902 f3a5 8b542410 }
		$sequence_3 = { 0f8423010000 8b13 68???????? 52 ffd6 83c408 85c0 }
		$sequence_4 = { e8???????? 48 8b4520 48 8b4878 48 }
		$sequence_5 = { 5b 81c4c8040000 c20800 a0???????? }
		$sequence_6 = { 8bc3 5f 5e 5b c3 b8???????? 83f901 }
		$sequence_7 = { 83c410 85c0 740a 68???????? e9???????? 8b442408 53 }
		$sequence_8 = { 53 33c0 56 8b742420 }
		$sequence_9 = { 83c151 57 51 ff5618 85c0 7404 31c0 }
		$sequence_10 = { ffd6 83c408 85c0 0f84990e0000 8b03 68???????? }
		$sequence_11 = { 7414 8b5640 8b4c2414 52 51 }
		$sequence_12 = { 55 e8???????? 8bd8 85db 0f84a0000000 56 }
		$sequence_13 = { 33c0 bade47773f 8d4848 f3aa }
		$sequence_14 = { c1ea18 33c3 8b1c95f0354000 8b56fc 33c3 8b1c8df0414000 }
		$sequence_15 = { 52 ff15???????? 8b4518 83c404 85c0 7517 a1???????? }

	condition:
		7 of them and filesize <140288
}
