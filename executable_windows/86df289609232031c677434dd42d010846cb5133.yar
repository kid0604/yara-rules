rule win_bachosens_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.bachosens."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bachosens"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7703 80c1e0 3ad1 7513 49ffc0 }
		$sequence_1 = { 660f1f840000000000 410fb707 418b3e 6603c1 4803f9 0fb7c0 }
		$sequence_2 = { 66443908 75f4 443bc1 740a b801000000 }
		$sequence_3 = { 49f7d9 4c8bc5 660f1f840000000000 420fb61407 410fb608 8d429f 3c19 }
		$sequence_4 = { 488bc7 ffc1 488d4001 803800 75f5 33d2 }
		$sequence_5 = { 75f3 418bc9 66390a 7417 }
		$sequence_6 = { 740e 488bc5 ffc2 488d4001 803800 }
		$sequence_7 = { 4c03d1 458b7220 418b521c 4c03f1 458b7a24 4803d1 }
		$sequence_8 = { 0fb70a 418d409f 6683f819 7704 }
		$sequence_9 = { 75f3 418bc9 66390a 7417 488bc2 0f1f840000000000 ffc1 }

	condition:
		7 of them and filesize <643072
}