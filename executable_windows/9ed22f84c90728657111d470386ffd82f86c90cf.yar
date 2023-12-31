rule win_kimsuky_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.kimsuky."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kimsuky"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 56 85ff 740a 33ff }
		$sequence_1 = { 8d95f0fcffff b9???????? e8???????? 8d95ecfbffff b9???????? e8???????? }
		$sequence_2 = { ff15???????? 85c0 7516 ff15???????? 8bd8 e8???????? }
		$sequence_3 = { 50 ffd6 8bd8 85db 7510 5e }
		$sequence_4 = { 833d????????00 7413 b801000000 8b4dfc 33cd e8???????? 8be5 }
		$sequence_5 = { 53 ffd7 a3???????? 8d85d4f5ffff }
		$sequence_6 = { 7503 56 eb18 6a00 6a00 6a00 68???????? }
		$sequence_7 = { 2bca 51 8d85e4f5ffff 50 6a00 6a00 }
		$sequence_8 = { 6a00 50 ff15???????? 8d85ecfbffff 50 8d85f8feffff }
		$sequence_9 = { 75af 4c897c2468 41bb01000000 418d5b02 4d85ed 740f 4d85e4 }
		$sequence_10 = { 4c03fd 448d4940 418b5750 4c897c2460 ffd6 458b4754 488bd5 }
		$sequence_11 = { ebdb 65488b042560000000 48897c2430 48896c2460 488b4818 41bb01000000 4c8b7120 }
		$sequence_12 = { 4533ff 4c89642428 4c896c2420 33f6 4533ed 4533e4 4c897c2468 }
		$sequence_13 = { 666666660f1f840000000000 418b0a 4903c9 4533c0 0fb601 0f1f4000 }
		$sequence_14 = { 4533c0 33d2 4883c9ff 4903de ff542468 4533c0 }
		$sequence_15 = { 428bbc0888000000 468b540f20 468b5c0f24 4d03d1 4d03d9 666666660f1f840000000000 }
		$sequence_16 = { 488d8a38000000 e9???????? 488d8a28010000 e9???????? }
		$sequence_17 = { 8b9590000000 0395d8000000 0395b8000000 8bbda0010000 }
		$sequence_18 = { 8bc2 c1e81f 03d0 69d290010000 3bca 7409 8b84afd0450300 }
		$sequence_19 = { ff15???????? 498bc6 488b4d20 4833cc }
		$sequence_20 = { 4c89642430 c744242880000000 c744242002000000 4533c9 4533c0 ba00000040 }
		$sequence_21 = { 8d4702 03c2 89442450 8bf0 }
		$sequence_22 = { 8b4c2468 c6043900 803f00 740d }
		$sequence_23 = { 85c0 7471 895c2468 8d4801 }
		$sequence_24 = { 83f809 8d7340 7405 be20000000 c68424a000000000 33d2 }
		$sequence_25 = { 85c0 0f94c1 85c9 0f8494020000 }
		$sequence_26 = { 8b83d8af0600 eb13 418d41ff 41be01000000 8983d8af0600 }
		$sequence_27 = { 8b848248960500 85c0 0f84cf000000 83f801 }
		$sequence_28 = { 8b83d8af0600 eb2b 448b83ccaf0600 41ffc0 }
		$sequence_29 = { 8b8424a0020000 488d542440 4c8bc3 89442420 }
		$sequence_30 = { 8b848248960500 85c0 746a 83f801 }

	condition:
		7 of them and filesize <1021952
}
