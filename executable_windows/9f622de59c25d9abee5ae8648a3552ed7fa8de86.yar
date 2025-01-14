rule win_glupteba_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.glupteba."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glupteba"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 50 ff15???????? 8d45d4 50 e8???????? 50 8d45d4 }
		$sequence_1 = { 0fb6c8 8bc1 c1e804 0bc1 40 d1f8 }
		$sequence_2 = { 83c0fc 33c9 85c0 7e0e 813c310d0a0d0a 7409 }
		$sequence_3 = { ff15???????? ff75ee ff15???????? 830bff ff45fc 8b45fc }
		$sequence_4 = { 50 68???????? e8???????? 83c420 e8???????? 5f 5e }
		$sequence_5 = { eb02 8a03 8807 47 }
		$sequence_6 = { 0bca 8b55fc c1ea07 c1e109 8d1c3f 0bd3 }
		$sequence_7 = { c1eb08 33f3 8b5dfc 33df }
		$sequence_8 = { 0106 830702 392e 75a0 }
		$sequence_9 = { 00cd 3e46 005e3e 46 }
		$sequence_10 = { 0012 3f 46 008bff558bec }
		$sequence_11 = { 0107 eb4d 8b02 89442418 }
		$sequence_12 = { 005e3e 46 00ff 3e46 }
		$sequence_13 = { 00ff 3e46 0012 3f }
		$sequence_14 = { 0101 03d3 8b4620 8bcb }
		$sequence_15 = { 00f1 3d46005e3e 46 00cd }

	condition:
		7 of them and filesize <1417216
}
