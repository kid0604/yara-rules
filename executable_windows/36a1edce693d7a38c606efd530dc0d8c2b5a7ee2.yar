rule win_bitsloth_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.bitsloth."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bitsloth"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83c40c 68???????? e8???????? 83c404 c645fc00 8d8d64f0ffff e8???????? }
		$sequence_1 = { c78564f9feff00000000 eb0b 1bc9 83c901 898d64f9feff }
		$sequence_2 = { 83c408 8d8de0faffff 51 8d95bcf1ffff 52 68c50b0000 8b4508 }
		$sequence_3 = { 8945ec 8b4d08 8b55e0 3b91a0af0600 7c02 eb44 }
		$sequence_4 = { 50 68???????? 68???????? 8b0d???????? 51 8b15???????? 52 }
		$sequence_5 = { e8???????? 8bc8 e8???????? 8b55bc 2bd0 8955cc 7446 }
		$sequence_6 = { 68???????? 8b55f8 52 ff15???????? 8945fc 837dfc00 7515 }
		$sequence_7 = { 8945c8 8945cc 68???????? 8b4d08 51 e8???????? 83c408 }
		$sequence_8 = { 51 8b55e0 8b02 8b4de0 51 8b908c000000 ffd2 }
		$sequence_9 = { 3b8568ffffff 721d 6a00 6a00 681f520000 e8???????? 83c40c }

	condition:
		7 of them and filesize <677888
}
