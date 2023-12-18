rule win_abaddon_pos_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.abaddon_pos."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.abaddon_pos"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7402 eb27 8b8600010000 03860c010000 89867c010000 8b8684010000 }
		$sequence_1 = { ba00000000 eb05 ba01000000 0186ac010000 }
		$sequence_2 = { 80beb801000001 751b 80fa30 7205 80fa39 7605 80fa20 }
		$sequence_3 = { 41 89c0 49 c7c100000000 ff15???????? 48 83c420 }
		$sequence_4 = { 48 8986d0050000 48 83ec20 48 c7c100000000 }
		$sequence_5 = { 89d8 69c080000000 3d002d0000 7602 eb22 }
		$sequence_6 = { 7318 807c1e2c41 720c 807c1e2c5a }
		$sequence_7 = { 81bea001000000dc0500 740c 81bea001000000d60600 7508 6a05 ff15???????? 8b86a0010000 }
		$sequence_8 = { 31c9 31d2 80beb401000001 7505 }
		$sequence_9 = { ffc3 ebd1 48 31db }
		$sequence_10 = { 8986b0050000 48 83ec20 48 8b8eb0050000 48 }
		$sequence_11 = { 0504d00700 48 8986c8050000 48 0504d00700 48 8986d0050000 }
		$sequence_12 = { 83f800 7502 ebe4 50 ff15???????? 6a00 6a00 }
		$sequence_13 = { 83c000 48 8b9eb8050000 48 8918 48 }
		$sequence_14 = { 0500040000 3b19 730f 311418 }
		$sequence_15 = { 720b 803939 7706 fe86a8010000 }

	condition:
		7 of them and filesize <40960
}
