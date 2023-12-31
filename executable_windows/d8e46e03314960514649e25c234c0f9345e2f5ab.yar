rule win_sedreco_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.sedreco."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sedreco"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 89450c 56 85c0 }
		$sequence_1 = { c645ff30 e8???????? 85c0 7505 }
		$sequence_2 = { 8bec 51 836d0804 53 }
		$sequence_3 = { 836d0804 53 56 8b750c }
		$sequence_4 = { 8b750c 56 e8???????? 6a08 }
		$sequence_5 = { 50 68???????? 6a0d 68???????? }
		$sequence_6 = { 51 6802020000 68???????? 50 }
		$sequence_7 = { 7411 6a04 68???????? 68???????? }
		$sequence_8 = { 7ce0 a1???????? 5e 85c0 }
		$sequence_9 = { ff15???????? 83c604 81fe???????? 7ce0 }
		$sequence_10 = { ffd6 8b0d???????? 898114010000 85c0 }
		$sequence_11 = { ffd6 8b0d???????? 898198000000 85c0 }
		$sequence_12 = { 56 be???????? 8b06 85c0 740f 50 }
		$sequence_13 = { ffd6 8b0d???????? 894160 85c0 }
		$sequence_14 = { ffd6 ffd0 a3???????? 5e 85c0 750a a1???????? }
		$sequence_15 = { 6a01 68???????? ff35???????? ff15???????? ffd0 }
		$sequence_16 = { 488b05???????? ff90e8000000 90 4883c420 }
		$sequence_17 = { 68???????? e8???????? 8b35???????? 83c404 6a00 68???????? 6aff }
		$sequence_18 = { 4889442420 41b906000200 4533c0 488b15???????? 48c7c101000080 488b05???????? ff9038010000 }
		$sequence_19 = { 6800010000 6a00 68???????? e8???????? 6800020000 }
		$sequence_20 = { ffd6 50 68???????? 6aff }
		$sequence_21 = { 488b0d???????? 488b05???????? ff5010 85c0 }
		$sequence_22 = { 50 68???????? 6aff 68???????? 6a00 6a00 ffd6 }
		$sequence_23 = { 4883c428 c3 48890d???????? c3 48895c2410 4889742418 55 }
		$sequence_24 = { 33d2 488d4c2450 488b05???????? ff90d8020000 }
		$sequence_25 = { 4533c9 4533c0 ba000000c0 488b0d???????? 488b05???????? ff5040 }
		$sequence_26 = { 448bc0 ba08000000 488b0d???????? ff15???????? 488905???????? }
		$sequence_27 = { 488b0d???????? 488b05???????? ff5028 48c705????????00000000 }
		$sequence_28 = { ffd6 8b4dfc 5f 5e 33cd b8???????? }
		$sequence_29 = { 7cd5 68???????? e8???????? 8b4dfc 83c404 }
		$sequence_30 = { 53 68???????? ff35???????? ffd6 ffd0 85c0 }
		$sequence_31 = { e8???????? 8b8c2424020000 5b 33cc 33c0 e8???????? }
		$sequence_32 = { 52 50 ff91f0000000 8bf0 }
		$sequence_33 = { a1???????? 33c5 8945fc 6a0a 8d45f4 50 51 }
		$sequence_34 = { 8d55f8 52 50 8b08 ff5124 }
		$sequence_35 = { c20c00 6a02 ff74240c ff74240c e8???????? c20800 ff74240c }
		$sequence_36 = { 57 50 ff512c 8bce }
		$sequence_37 = { ff512c 8bf0 f7de 1bf6 46 }
		$sequence_38 = { 8945fc 8b45f0 8945f4 8b45f4 }
		$sequence_39 = { 50 8b08 ff9180000000 8b06 }
		$sequence_40 = { ff512c 8bce 8bd8 e8???????? 57 }
		$sequence_41 = { 57 c785ecfeffff01000000 c785e8feffffe197af54 0f6e85e8feffff 0f72f002 }
		$sequence_42 = { 83ec24 53 56 57 c745dce197af54 }
		$sequence_43 = { 8d443001 6a00 51 50 }
		$sequence_44 = { 8d7901 8d4c2420 57 ff15???????? 84c0 }
		$sequence_45 = { 6800040000 51 56 8974242c ff15???????? 85c0 0f8484010000 }
		$sequence_46 = { 51 52 ff15???????? 8b442410 8b4e10 }
		$sequence_47 = { a1???????? 8b00 8b4c2420 88440c18 }
		$sequence_48 = { 85db 7548 fec8 53 b9???????? 8842ff }
		$sequence_49 = { e8???????? 8a54240b 83c404 8b4c2430 895c2410 3bcb }
		$sequence_50 = { 52 56 50 ff15???????? 6a01 }
		$sequence_51 = { 8d442428 c684244010000001 8b11 8d4c2418 52 56 }

	condition:
		7 of them and filesize <1586176
}
