rule win_smokeloader_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.smokeloader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.smokeloader"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 8d45f0 50 8d45e8 50 8d45e0 50 }
		$sequence_1 = { 50 8d45e0 50 56 ff15???????? 56 ff15???????? }
		$sequence_2 = { 6a00 53 ff15???????? 8d45f0 }
		$sequence_3 = { 57 ff15???????? 6a00 6800000002 6a03 6a00 6a03 }
		$sequence_4 = { 8bf0 8d45dc 50 6a00 53 }
		$sequence_5 = { 0fb64405dc 50 8d45ec 50 }
		$sequence_6 = { e8???????? 8bf0 8d45fc 50 ff75fc 56 }
		$sequence_7 = { 740a 83c104 83f920 72f0 }
		$sequence_8 = { 50 56 681f000f00 57 }
		$sequence_9 = { 56 8d45fc 50 57 57 6a19 }
		$sequence_10 = { ff15???????? bf90010000 8bcf e8???????? }
		$sequence_11 = { 668ce8 6685c0 7406 fe05???????? }
		$sequence_12 = { 56 ff15???????? 50 56 6a00 ff15???????? }
		$sequence_13 = { 8b07 03c3 50 ff15???????? }
		$sequence_14 = { 33c0 e9???????? e8???????? b904010000 }
		$sequence_15 = { 6a40 56 6a01 8d45f8 50 }
		$sequence_16 = { 03e8 03e9 81e5ff000000 8a442c18 88443c18 47 }
		$sequence_17 = { 8bde 8bfe 399c241c010000 7644 8b6c2410 47 }
		$sequence_18 = { 0fb64c3c18 0fb6c2 03c8 81e1ff000000 8a440c18 30042b 43 }
		$sequence_19 = { 8d8de8fdffff 50 50 50 }
		$sequence_20 = { 8985ecfdffff ffb5f0fdffff 50 53 e8???????? }
		$sequence_21 = { 8d85f0fdffff 8b750c 8b7d10 50 57 56 }
		$sequence_22 = { 89c6 6804010000 56 57 }
		$sequence_23 = { 8b4514 898608020000 56 6aff }
		$sequence_24 = { 53 e8???????? 8d8decfdffff 8d95f0fdffff }
		$sequence_25 = { c60653 56 6a00 6a00 }
		$sequence_26 = { 8d95f0fdffff c70200000000 6800800000 52 }
		$sequence_27 = { 89e5 81ec5c060000 53 56 }
		$sequence_28 = { fc 5f 5e 5b }
		$sequence_29 = { 60 89c6 89cf fc }
		$sequence_30 = { 30d0 aa e2f3 7505 }
		$sequence_31 = { 89cf fc b280 31db a4 b302 }
		$sequence_32 = { 4d 01c4 ffc9 49 }
		$sequence_33 = { 48896c2410 4889742418 57 4883ec30 65488b042560000000 4c8b15???????? }
		$sequence_34 = { 4883f814 72ea 488b0d???????? ff15???????? 488b0d???????? ff15???????? 488b0d???????? }
		$sequence_35 = { 8bd7 4c8bc3 4889442420 ff15???????? 488b0b ff15???????? 8a08 }
		$sequence_36 = { 41b800300000 ff15???????? 448b4754 488bd6 }
		$sequence_37 = { 55 89e5 81ec54040000 53 }
		$sequence_38 = { 01c2 31c0 ac 01c2 85c0 }
		$sequence_39 = { 488bd8 ff15???????? 4c8d4c2454 4c8d44244c }
		$sequence_40 = { 8b4b18 45 8b6320 4d }
		$sequence_41 = { 49 8d3c8c 8b37 4c 01c6 }
		$sequence_42 = { 8b7b24 4c 01c7 668b0c4f 41 8b7b1c }
		$sequence_43 = { 01c7 8b048f 4c 01c0 }
		$sequence_44 = { 8b4da0 8b55b8 89516c 687cda686e 8b45e4 50 }
		$sequence_45 = { 8945f8 8b45f8 8b4868 894df4 }
		$sequence_46 = { 31d1 75ec 58 29c6 d1ee }
		$sequence_47 = { 57 007508 bbb84340c1 4a }
		$sequence_48 = { 5b c9 c20800 55 89e5 83ec04 }
		$sequence_49 = { aa e2f3 7506 7404 }
		$sequence_50 = { 8b4da0 8b5580 895150 681256e9cc 8b45e4 50 }
		$sequence_51 = { 3345e4 8845e3 8b4dfc 034d10 8b55f0 0355fc 034df8 }
		$sequence_52 = { 01e8 31c9 c1c108 3208 40 }
		$sequence_53 = { 8b5514 0355b4 39559c 7316 }
		$sequence_54 = { 8b453c 8b7c2878 01ef 8b7720 01ee 56 }
		$sequence_55 = { 1e 53 56 57 }
		$sequence_56 = { 29c6 d1ee 037724 0fb7442efe }
		$sequence_57 = { 394dfc 750e 8b55e4 2b5510 8b45f8 2bc2 8945f8 }
		$sequence_58 = { eb0b 8b5508 0355f0 8a45ed 8802 8b4d10 034dfc }
		$sequence_59 = { 8bec 83ec08 8b4510 2d10bf3400 8b4d0c c1e103 }
		$sequence_60 = { 5d 5d a2???????? 95 }
		$sequence_61 = { 17 c74424fc7c2e0000 83ec04 7504 7402 6d }
		$sequence_62 = { ad 37 5d 0aa228b9a2ce c9 5d }
		$sequence_63 = { d4ad d6 1d51d61d41 d6 1d55d89d52 }
		$sequence_64 = { a2???????? ed d6 104ddc 9c }

	condition:
		7 of them and filesize <245760
}
