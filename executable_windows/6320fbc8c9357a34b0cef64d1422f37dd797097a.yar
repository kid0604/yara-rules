rule win_bankshot_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.bankshot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bankshot"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bf8 8d5101 8a01 41 84c0 75f9 57 }
		$sequence_1 = { 81ec48040000 a1???????? 33c5 8945f8 53 }
		$sequence_2 = { 7ccb 3bca 0f8d20f8ffff 0f1f00 80b40ddc3dffffaa 41 }
		$sequence_3 = { 83faff 747b 33c9 85d2 7e77 }
		$sequence_4 = { 83c40c e8???????? 99 b907000000 }
		$sequence_5 = { 57 50 e8???????? 83c40c 6b45e430 8945e0 8d80d0e10110 }
		$sequence_6 = { 8d90c4e10110 5f 668b02 8d5202 668901 8d4902 83ef01 }
		$sequence_7 = { 8bb5a838ffff 8d8db438ffff 68???????? 894608 c70610000000 c7460400000000 }
		$sequence_8 = { 8945e0 8d80d0e10110 8945e4 803800 8bc8 7435 8a4101 }
		$sequence_9 = { ffd7 c785c03affff00000000 8b85bc3affff 85c0 }
		$sequence_10 = { 85db 7507 c746340c7b0110 57 ff7634 }
		$sequence_11 = { e8???????? 83c404 89861c020000 8b45e0 8d4e0c 6a06 8d90c4e10110 }
		$sequence_12 = { 7515 8b45fc 817848b8e40110 7409 ff7048 e8???????? 59 }
		$sequence_13 = { c7832005000000008000 eb4e b9???????? 8d85d4fdffff }
		$sequence_14 = { e9???????? 57 33ff 8bcf 8bc7 894de4 3998c0e10110 }
		$sequence_15 = { 8b4508 c700???????? 8b4508 898850030000 8b4508 59 c74048b8e40110 }
		$sequence_16 = { 0f10440b10 0f28ca 660fefc8 0f114c0b10 83c120 3bce 7cd9 }
		$sequence_17 = { 33c0 8996a0af0600 668b04dd66734100 83fb02 898694af0600 }
		$sequence_18 = { 83c101 894df8 837df803 0f83d2000000 6a04 }
		$sequence_19 = { eb3a 81c694010000 740e f30f7e06 660fd685ccfeffff eb24 }
		$sequence_20 = { 7506 8d4707 50 eb01 57 8d7e10 }
		$sequence_21 = { 894df8 837dd8ff 7464 6a00 }
		$sequence_22 = { ff15???????? 4885c0 0f8482000000 48ffc3 4a89042f 488d3cdd00000000 }
		$sequence_23 = { 41 890d???????? 33c0 8b4df4 64890d00000000 }
		$sequence_24 = { 44897c2420 ff15???????? 488bf8 83caff }
		$sequence_25 = { 0f84b6000000 488d3ded3e0000 498bf0 b903000000 f3a6 }
		$sequence_26 = { ba7a341200 488bcf 8905???????? e8???????? 488d0d7d2b0000 }
		$sequence_27 = { 23f0 68???????? 89b564f2ffff ffd7 68???????? 50 ffd3 }
		$sequence_28 = { 81fae7030000 7708 81c2e8030000 8910 8b0b 6a00 68e6210000 }
		$sequence_29 = { c705????????01000000 c705????????05000000 66c705????????3c00 c705????????04000000 e8???????? 68???????? }
		$sequence_30 = { 0f859b010000 c745e068410110 8b4508 8bcf }
		$sequence_31 = { 85c0 7543 8b542454 8d4c2458 6884140000 }
		$sequence_32 = { ff15???????? 68???????? 57 8985ccfbffff ff15???????? }
		$sequence_33 = { 8bec 8b4508 57 8d3c85108c7100 8b0f 85c9 }
		$sequence_34 = { 52 e8???????? 8bf0 83c414 f7de 1bf6 }
		$sequence_35 = { 837d0c00 7455 8b4d0c 51 ff15???????? }
		$sequence_36 = { ff15???????? 488d1556ea0000 488d4c2420 488905???????? ff15???????? 807c242000 }
		$sequence_37 = { 448bc1 4a8d4c0d00 4903d4 e8???????? 488b461c ffc7 4883c328 }
		$sequence_38 = { 52 50 e8???????? 6a02 8d8c24b0080000 6a00 8d54244c }
		$sequence_39 = { 3bd1 7f1e 6b0d????????3c 030d???????? }
		$sequence_40 = { 56 57 6884140000 6a40 ff15???????? 8bd8 }
		$sequence_41 = { e8???????? 488d0de3330000 e8???????? 488d0d87990000 e8???????? 84c0 0f85b6000000 }
		$sequence_42 = { 8b4c2430 896804 895008 89480c e8???????? }
		$sequence_43 = { 50 e8???????? 83c404 898568f8ffff 8d8df4fdffff 51 }
		$sequence_44 = { ff15???????? 488bf8 4885c0 0f84b5000000 }

	condition:
		7 of them and filesize <860160
}
