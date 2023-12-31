rule win_unidentified_080_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.unidentified_080."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_080"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a40 8d8578ffffff 53 50 899d74ffffff e8???????? b801000000 }
		$sequence_1 = { 7502 8bc1 8bcb 894308 e8???????? 8b4328 89732c }
		$sequence_2 = { 6a00 ff15???????? 85c0 7451 8d8df4fdffff 51 }
		$sequence_3 = { 8d4110 894608 89460c eb1d 3bcb 740d 391e }
		$sequence_4 = { c745ec8c2f0210 3bc3 740e 395da0 7509 50 }
		$sequence_5 = { 8975f8 3bc3 7457 8b4dfc 8d5508 52 56 }
		$sequence_6 = { 7411 8b45f8 57 56 50 e8???????? 83c40c }
		$sequence_7 = { 85c0 7409 53 57 56 ff15???????? }
		$sequence_8 = { ebd9 8915???????? 8d55c4 c745c078310210 52 c745bcffffffff c745c090310210 }
		$sequence_9 = { 83c40c 6a04 8d75d4 895dd4 895dd8 895ddc 895de0 }

	condition:
		7 of them and filesize <392192
}
