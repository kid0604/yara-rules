rule win_purplefox_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.purplefox."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.purplefox"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 33c0 48898500040000 8bd8 4c899df8030000 90 }
		$sequence_1 = { 64bba3ae1c94 af 6c 7924 5e 52 }
		$sequence_2 = { 488d05fc900000 488b4c2430 483bc8 7405 e8???????? 488b05???????? }
		$sequence_3 = { 8b0a 6a00 51 6800000100 50 ff15???????? 8bf0 }
		$sequence_4 = { 4c8b642450 0f84c5000000 488364242000 488d05e17f0000 c64424600d 4a8b0ce0 }
		$sequence_5 = { e8???????? e9???????? 8b570c 8b4708 }
		$sequence_6 = { 750a b80d0000c0 e9???????? 488d7768 }
		$sequence_7 = { 0f88c9000000 488b4c2460 ff15???????? 4839442470 0f85b3000000 488d542460 488bce }
		$sequence_8 = { 488d4c2420 e8???????? eb1e 488b5710 488d0d21b10000 e8???????? 488b5710 }
		$sequence_9 = { 85c0 0f88c7010000 4c8b05???????? 488b8d08040000 488d442470 }
		$sequence_10 = { d565 96 dcb2503c62fc b23e ac 82d0e0 e460 }
		$sequence_11 = { 55 8bec 33c0 8b4d08 3b0cc528bb4000 740a 40 }
		$sequence_12 = { e8???????? 488b5710 488d4c2420 e8???????? }
		$sequence_13 = { 56 6a1b 52 ffd7 85c0 7918 6a00 }
		$sequence_14 = { 8bd8 85c0 0f8882000000 c744246800010000 4889742460 89742458 }
		$sequence_15 = { 6a00 6a00 68000000c0 68???????? ff15???????? 8985e0fdffff }
		$sequence_16 = { ff75e0 ff15???????? c9 c20800 6a00 6800100000 }
		$sequence_17 = { 488d0d1b0f0000 ff15???????? 8bc7 eb02 33c0 }
		$sequence_18 = { 348a 90 be7c1a1278 04b2 7a00 bc0ad47a56 }
		$sequence_19 = { 9c f5 83c506 66892424 }
		$sequence_20 = { 488bc8 ff15???????? 488d1528460000 488bce 488905???????? ff15???????? 488bc8 }
		$sequence_21 = { 57 56 6a0b ffd3 3d040000c0 750d }
		$sequence_22 = { 8945d0 8945d4 8945dc c745d880000000 }
		$sequence_23 = { e9???????? 0fa3c3 8d861cae46c3 66b8f230 8b4500 }
		$sequence_24 = { 488d0d55100000 ff15???????? 488b6c2450 8bc3 488b5c2468 }
		$sequence_25 = { ff15???????? 8bc3 4881c4d0000000 5e 5b 5d c3 }
		$sequence_26 = { 8d45ec e8???????? 33c0 0175dc 6800040000 }
		$sequence_27 = { 83e61f 8d3c85000c4100 8b07 c1e606 f644300401 }
		$sequence_28 = { 7681 f1 6c 3c9f 7d8b 017b29 }
		$sequence_29 = { 8d95defdffff 33c9 52 8945f8 8945f4 8945f0 }
		$sequence_30 = { 488d3d4c610000 eb0e 488b03 4885c0 7402 }
		$sequence_31 = { 0483 bd1d8f909a 30a563491b40 5e a0???????? 4b }
		$sequence_32 = { 6800020000 50 ff15???????? 85c0 790a 8b4df8 ffd3 }
		$sequence_33 = { 8978f0 8b4df8 8948f4 c740e001000000 c740e40d000000 }
		$sequence_34 = { 89df 2cfd 60 60 c0e002 b02e f9 }
		$sequence_35 = { 51 50 e8???????? 85c0 7417 c70701000000 8b07 }
		$sequence_36 = { 81fe00000001 7708 81c600100000 eb9b 8d4dc4 51 ff15???????? }
		$sequence_37 = { 56 e8???????? 8bc6 c1f805 8b0485000c4100 83e61f c1e606 }
		$sequence_38 = { 488d1578900000 483950f0 740b 488b10 4885d2 7403 }
		$sequence_39 = { 48895c2418 55 56 57 4883ec30 488d3da9b40000 33ed }

	condition:
		7 of them and filesize <1983488
}
