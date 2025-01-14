rule win_ramnit_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.ramnit."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ramnit"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 5a 5b c9 c20400 55 8bec }
		$sequence_1 = { 5e 5f 59 5a }
		$sequence_2 = { 51 52 8b4508 8b5d0c 4b f7d3 23c3 }
		$sequence_3 = { 51 52 8b4508 8b5d0c }
		$sequence_4 = { 8b7510 3b7514 7705 3b7d0c 7602 }
		$sequence_5 = { b800000000 59 5f 5e 5a 5b c9 }
		$sequence_6 = { 7434 837d1000 742e 837d1400 7428 }
		$sequence_7 = { 8bec 8b4508 3b450c 7603 8b450c c9 c20800 }
		$sequence_8 = { f7d0 48 59 5f }
		$sequence_9 = { 7512 47 46 e2f6 b801000000 59 }

	condition:
		7 of them and filesize <470016
}
