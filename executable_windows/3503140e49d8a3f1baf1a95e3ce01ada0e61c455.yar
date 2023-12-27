rule win_unidentified_092_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.unidentified_092."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_092"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c78520ffffff00000000 c68510ffffff00 83f810 7241 8b8df8feffff 40 3d00100000 }
		$sequence_1 = { 723f 8b4c2464 40 3d00100000 722a f6c11f 0f850b010000 }
		$sequence_2 = { 33f1 8b7df8 0375a4 8bd3 8b5dfc f7d2 8b4de8 }
		$sequence_3 = { 8b41fc 3bc1 0f83de020000 2bc8 83f904 0f82d3020000 83f923 }
		$sequence_4 = { 0155ec c1c107 33f1 8bcb 8bd3 }
		$sequence_5 = { 56 52 50 8b08 ff511c c745fcffffffff 83ceff }
		$sequence_6 = { 8d8558ffffff 50 0f118568ffffff ffd3 c645fc03 83ec10 }
		$sequence_7 = { 8bc3 c1c007 8bcb 33d0 897508 f7d1 8bc3 }
		$sequence_8 = { 83ee01 75e9 8b85e4fbffff 83f814 }
		$sequence_9 = { 50 56 ffd3 85c0 7f38 68???????? }

	condition:
		7 of them and filesize <10202112
}