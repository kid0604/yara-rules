rule win_poweliks_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.poweliks."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poweliks"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { eb0b 8b5118 ebc9 8b5dec 8b75e8 8b45f8 8b0c87 }
		$sequence_1 = { c745b4726f6341 c745b864647265 66c745bc7373 c645be00 8bc8 57 }
		$sequence_2 = { 83ff0c 7439 3bc8 75ce 8b5508 }
		$sequence_3 = { 8d5598 33ff 2bf2 8d147e 8a541598 32547d98 }
		$sequence_4 = { 7415 8b7d08 8b720c 81c704110000 03f7 8b7a04 }
		$sequence_5 = { 663b4b06 7333 8b4a08 8b32 3bce 7602 8bce }
		$sequence_6 = { 33c9 663b4b06 7333 8b4a08 8b32 3bce 7602 }
		$sequence_7 = { 57 0fb65dfe 81e307000080 7905 4b }
		$sequence_8 = { 8b3486 8365fc00 03ca 894df4 8d45d0 03f2 2945f4 }
		$sequence_9 = { 3a5c0db0 7506 40 83f80f }

	condition:
		7 of them and filesize <115712
}
