rule win_bubblewrap_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.bubblewrap."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bubblewrap"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 68???????? 68???????? e8???????? 8b08 83c408 890d???????? 8b5004 }
		$sequence_1 = { ffd6 8d542464 68???????? 52 ffd6 b900020000 }
		$sequence_2 = { 56 57 6a02 8d442418 33f6 55 50 }
		$sequence_3 = { 880c1a 83c9ff f2ae f7d1 49 8d7c1a01 8bd1 }
		$sequence_4 = { 81ec08020000 53 56 57 ff15???????? }
		$sequence_5 = { f3a5 6870010000 e8???????? 8d442448 50 6870010000 }
		$sequence_6 = { 8d6ced00 89542418 c1e503 8bc5 8bdd 25ff030000 }
		$sequence_7 = { 880f 8810 7c89 5d 5f 5e 5b }
		$sequence_8 = { c644241f78 c644242011 c644242106 c644242274 }
		$sequence_9 = { 83c404 a801 740d 8d54240c 52 e8???????? 83c404 }

	condition:
		7 of them and filesize <57136
}