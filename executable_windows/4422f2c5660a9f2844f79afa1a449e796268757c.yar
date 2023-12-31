rule win_bart_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.bart."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bart"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b0483 3bd0 772e 7205 80c1ff 79e8 33c9 }
		$sequence_1 = { 8b0433 03c2 03c1 3bc2 7404 1bc9 }
		$sequence_2 = { 8a18 894dd0 8955c8 8945cc 57 85f6 }
		$sequence_3 = { 660fd6459c e8???????? 83c410 8d8570ffffff 33c9 ba07000000 }
		$sequence_4 = { e8???????? 8b7598 8d4d9c 8b5590 0fb606 }
		$sequence_5 = { 8b4485dc d3e8 88043a 0fbed3 3bd6 7cde 8bbd58ffffff }
		$sequence_6 = { 7868 8bc8 0fbec2 8b5508 894c2418 8d1482 8a44240e }
		$sequence_7 = { 84db 0f8ed3020000 0fb6d3 8bc7 899564ffffff 0b08 8d4004 }
		$sequence_8 = { 8bca e8???????? 8b4dfc 83c438 33cd 5f 5e }
		$sequence_9 = { 0f88ff000000 8b7df4 83c706 42 }

	condition:
		7 of them and filesize <163840
}
