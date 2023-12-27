rule win_corebot_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.corebot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.corebot"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8a1c08 84db 741c 01c8 }
		$sequence_1 = { b907000000 0fb610 8955e8 c745ec07000000 8d0412 84d2 8945e8 }
		$sequence_2 = { c70600000000 31c0 5e 5d c20800 55 }
		$sequence_3 = { 85c0 7418 8b0e 6a00 ff750c ff7508 }
		$sequence_4 = { a2???????? 8035????????01 8035????????02 8035????????03 8035????????04 }
		$sequence_5 = { 8b45d8 8d4801 894dd8 b907000000 0fb618 }
		$sequence_6 = { ff7508 51 ff15???????? 85c0 0f95c0 eb08 }
		$sequence_7 = { 8b31 85f6 7410 89f1 e8???????? 56 }
		$sequence_8 = { ff15???????? 807e5000 7509 ff764c ff15???????? 8d4634 50 }
		$sequence_9 = { ff15???????? 8d4634 50 ff15???????? 8d4e0c e8???????? }
		$sequence_10 = { 807e5800 7509 ff7654 ff15???????? 807e5000 7509 }
		$sequence_11 = { 85ff 740f 57 ff7508 }
		$sequence_12 = { 85c0 7515 8b4624 3b4620 }
		$sequence_13 = { ff7010 ff7014 e8???????? 8b45e0 }
		$sequence_14 = { eb10 6800800000 6a00 56 }
		$sequence_15 = { ff742428 e8???????? 8b442424 8d4c2410 }

	condition:
		7 of them and filesize <1302528
}