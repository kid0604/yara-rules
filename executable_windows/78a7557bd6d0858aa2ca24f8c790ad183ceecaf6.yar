rule win_daxin_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.daxin."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.daxin"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 2bc2 d1f8 99 f7f9 }
		$sequence_1 = { 413bd5 7209 438d443500 3bd0 7226 }
		$sequence_2 = { e9???????? 448b4f04 4533c0 ba02000000 488bcb }
		$sequence_3 = { 448b4004 0fb7c1 c1e910 66c1c008 0fb7d0 }
		$sequence_4 = { 740d 488bcb e8???????? e9???????? 33c9 }
		$sequence_5 = { 7508 488bc8 ff5028 eb02 33c0 }
		$sequence_6 = { 57 4154 4883ec20 4533c0 }
		$sequence_7 = { ff15???????? 884708 4c8b8380000000 4d85c0 }
		$sequence_8 = { 885303 7e1b 8b74241c 8bcf }
		$sequence_9 = { 8854243b 8b54243b 81e2ff000000 03c2 }
		$sequence_10 = { 88540e07 885c3e08 7cd2 897e04 }
		$sequence_11 = { 88543908 8a443108 02c2 25ff000000 }
		$sequence_12 = { 8854243a 8b54243a 81e2ff000000 03c2 }
		$sequence_13 = { 885017 8bd1 c1e902 f3a5 8bca }
		$sequence_14 = { 88502a 8bda 8b4ca814 2bca }

	condition:
		7 of them and filesize <3475456
}
