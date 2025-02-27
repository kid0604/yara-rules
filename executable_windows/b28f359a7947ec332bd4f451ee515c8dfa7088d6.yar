rule win_matsnu_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.matsnu."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matsnu"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 751d ff75ba ff7510 e8???????? 8945f6 }
		$sequence_1 = { 2945ce ebd3 c745d600000000 c745da00010000 c745e200000000 }
		$sequence_2 = { 8b45e6 8807 eb75 817dd6000f0000 }
		$sequence_3 = { c1e004 8b7dfa 01c7 8b45de 8907 8b45e6 c1e004 }
		$sequence_4 = { 8b75fa 01c6 8b36 0375ea 8b7d10 }
		$sequence_5 = { 7402 eb14 8d75f9 56 }
		$sequence_6 = { 8b450c 8985c0fbffff 50 ff7508 }
		$sequence_7 = { 8a4e01 80e1f0 c0e904 08c8 8d55bc 01c2 8a02 }
		$sequence_8 = { e8???????? 83f800 750f c785a4fbffff03000000 e9???????? }
		$sequence_9 = { 55 89e5 81ec10020000 c785f0fdffff00000000 }

	condition:
		7 of them and filesize <606992
}
