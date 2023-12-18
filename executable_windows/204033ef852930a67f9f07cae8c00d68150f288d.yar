rule win_starsypound_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.starsypound."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.starsypound"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 8dbc2458010000 83c9ff 33c0 }
		$sequence_1 = { 68???????? 52 e8???????? 83c420 85c0 7444 8b5304 }
		$sequence_2 = { 53 56 57 6a18 e8???????? 8bb42424040000 }
		$sequence_3 = { 8d4c2428 68???????? 51 e8???????? 56 8d542434 }
		$sequence_4 = { 8bfd 8d44240c f3a5 8b5500 8b3d???????? 6a00 }
		$sequence_5 = { 885c3438 c744241804010000 ff15???????? 8dbc2458010000 83c9ff 33c0 }
		$sequence_6 = { 50 8d4c2424 56 51 52 }
		$sequence_7 = { f3a4 885c0444 bf???????? 83c9ff 33c0 33f6 }
		$sequence_8 = { 83c40c 85c0 7e2b eb08 }
		$sequence_9 = { e8???????? 68c0270900 ff15???????? e8???????? 5f }

	condition:
		7 of them and filesize <40960
}
