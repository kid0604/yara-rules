rule win_qhost_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.qhost."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.qhost"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c60000 8b4dfc 83e901 894dfc ebdc 8b4508 }
		$sequence_1 = { 40 884598 8b0d???????? 51 e8???????? }
		$sequence_2 = { ff15???????? 898550beffff c78538beffff00000000 837df400 }
		$sequence_3 = { 7507 b805000080 eb36 8b5508 52 68???????? e8???????? }
		$sequence_4 = { 03d0 52 ff15???????? 83c408 }
		$sequence_5 = { 68???????? 68???????? 68ff030000 68???????? ff15???????? 83c410 }
		$sequence_6 = { 837df800 0f84dc000000 c7854cbeffff00000000 c78550beffff00000000 eb1e }
		$sequence_7 = { 68???????? 680f270000 68???????? ff15???????? 83c410 ff15???????? }
		$sequence_8 = { 8bec 81ec6c0b0000 c785f0fdffff00000000 c785e8fdffff00000000 c785d4fdffff00000000 c745fc00000000 c785f4fdffff00000000 }
		$sequence_9 = { 50 6800040000 8d8d00fcffff 51 8b95c8fbffff 52 }

	condition:
		7 of them and filesize <286720
}
