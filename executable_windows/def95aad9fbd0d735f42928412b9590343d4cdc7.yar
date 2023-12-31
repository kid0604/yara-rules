rule win_prikormka_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.prikormka."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prikormka"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d0446 50 e8???????? 83c40c 6a00 56 }
		$sequence_1 = { 8d1446 52 e8???????? 83c40c }
		$sequence_2 = { ffd3 8b2d???????? 85c0 7405 }
		$sequence_3 = { 51 e8???????? 83c40c 68???????? ffd7 }
		$sequence_4 = { 85f6 7420 68???????? ffd7 }
		$sequence_5 = { ff15???????? 68???????? ffd7 03c0 50 }
		$sequence_6 = { 8b1d???????? 83c40c 6a00 56 ffd3 8b2d???????? }
		$sequence_7 = { 56 ffd3 85c0 7405 6a02 56 }
		$sequence_8 = { 740e 68???????? 50 ff15???????? ffd0 }
		$sequence_9 = { 68???????? 6a00 6a00 ff15???????? 85c0 7502 59 }
		$sequence_10 = { 83c40c 8d442404 50 ff15???????? 5e }
		$sequence_11 = { 7408 41 42 3bce }
		$sequence_12 = { 85c0 7502 59 c3 50 ff15???????? b801000000 }
		$sequence_13 = { c3 57 6a00 6a00 6a00 6a02 }
		$sequence_14 = { 68???????? ff15???????? 0fb7c0 6683f805 }
		$sequence_15 = { ff15???????? ffd0 c705????????01000000 c705????????01000000 }
		$sequence_16 = { 5e 85c0 7422 68???????? 50 }
		$sequence_17 = { 0fb7c0 6683f805 7d09 b801000000 }
		$sequence_18 = { 5e 85c0 7414 c705????????01000000 }
		$sequence_19 = { 33f6 e8???????? e8???????? e8???????? e8???????? e8???????? e8???????? }
		$sequence_20 = { 50 e8???????? 8b2d???????? 83c40c 6a00 }
		$sequence_21 = { ff15???????? 8bf0 ff15???????? 3db7000000 751f 56 }
		$sequence_22 = { 83c102 6685d2 75f5 2bce 8d1400 52 d1f9 }
		$sequence_23 = { 75f5 8b0d???????? 2bc2 8b15???????? d1f8 }
		$sequence_24 = { 751f 56 ff15???????? 33c0 }
		$sequence_25 = { 6685c9 75f5 2bc6 8d0c12 }
		$sequence_26 = { 2bc6 8d0c12 51 d1f8 }
		$sequence_27 = { 8b35???????? 83c40c 68???????? ffd6 03c0 }
		$sequence_28 = { 50 e8???????? b8???????? 83c40c 8d5002 }
		$sequence_29 = { 75f5 8d0c12 2bc6 51 d1f8 8d544408 }
		$sequence_30 = { d1f8 8d7102 8da42400000000 668b11 83c102 }
		$sequence_31 = { 85c0 7409 6a02 68???????? }
		$sequence_32 = { 50 ff15???????? 0fb74c2416 0fb7542414 }
		$sequence_33 = { d1f8 8bd0 b8???????? 8d7002 8da42400000000 668b08 83c002 }
		$sequence_34 = { 6685c9 75f5 2bc2 b9???????? d1f8 8d7102 668b11 }
		$sequence_35 = { ffd6 50 68???????? 57 ffd6 03c7 50 }
		$sequence_36 = { 56 57 68???????? 33ff 57 57 ff15???????? }
		$sequence_37 = { e8???????? 83c40c eb0d 6a00 6800020000 }
		$sequence_38 = { d1f8 8d7102 668b11 83c102 6685d2 75f5 8d1400 }
		$sequence_39 = { 6685d2 75f5 8d1400 2bce 52 d1f9 }
		$sequence_40 = { 6a00 6800020000 ff15???????? 68???????? }
		$sequence_41 = { e8???????? 83c40c 6a00 68???????? ffd3 85c0 7409 }
		$sequence_42 = { 6a5c 99 5f f7ff 83f801 }
		$sequence_43 = { 0f87f5090000 ff248505eb0010 33c0 838df4fbffffff 8985a0fbffff }
		$sequence_44 = { 48 48 8975f4 7479 83e848 745f }
		$sequence_45 = { 56 8bc3 2bc1 6a5c 99 }
		$sequence_46 = { 32a832d232e0 32e6 3209 3310 3329 333d???????? 335f33 }

	condition:
		7 of them and filesize <401408
}
