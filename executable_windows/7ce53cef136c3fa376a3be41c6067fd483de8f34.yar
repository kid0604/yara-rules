rule win_aytoke_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.aytoke."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.aytoke"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6685c9 75e9 e9???????? 33c0 8bff 0fb788103a4100 66898c05fcfdffff }
		$sequence_1 = { 3c58 770f 0fbec2 0fbe80f83b4100 83e00f eb02 33c0 }
		$sequence_2 = { 8bd0 83e01f c1fa05 8b149500c44100 59 c1e006 59 }
		$sequence_3 = { 56 e8???????? c1f805 56 8d3c8500c44100 e8???????? 83e01f }
		$sequence_4 = { 90 68???????? e8???????? a1???????? 46 83c004 }
		$sequence_5 = { 2bc2 bb5c000000 85c0 7e16 }
		$sequence_6 = { be01000000 83c104 83c408 3bce }
		$sequence_7 = { 33c0 8d642400 0fb7888c3a4100 66898c05fcfdffff 83c002 6685c9 75e9 }
		$sequence_8 = { 85ff 7424 56 53 6a01 57 }
		$sequence_9 = { 663bc1 0f85cc130000 8d95fcfcffff 52 ff15???????? 68a0000000 }

	condition:
		7 of them and filesize <425984
}
