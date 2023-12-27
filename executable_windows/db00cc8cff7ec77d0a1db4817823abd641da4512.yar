rule win_plead_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.plead."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.plead"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 85c0 750c c745fcfcffffff e9???????? 395d18 }
		$sequence_1 = { ebda 33f6 c745fcf8ffffff 3bf7 }
		$sequence_2 = { bf00800000 57 53 56 897d14 }
		$sequence_3 = { e8???????? 817d14e8030000 53 56 }
		$sequence_4 = { 59 5e c20400 8b4c2404 56 }
		$sequence_5 = { 50 ff15???????? 6a3f 33c0 59 }
		$sequence_6 = { 8d4dfc 51 8d4dd8 51 }
		$sequence_7 = { 8d4514 53 50 56 53 6a05 }
		$sequence_8 = { ff15???????? 50 ff15???????? 33c0 81c418020000 }
		$sequence_9 = { 5e 5b 33c0 81c418020000 c21000 8b84241c020000 }
		$sequence_10 = { 7cf1 ffd3 8b35???????? 2bc7 3de8030000 }
		$sequence_11 = { 8b5508 52 ff15???????? 6aff a1???????? 50 ff15???????? }
		$sequence_12 = { 50 8b1d???????? ffd3 85c0 743b }
		$sequence_13 = { 8b8c241c020000 68???????? 51 ff15???????? }
		$sequence_14 = { 5d 8a44341c 32c2 8844341c 46 3bf1 }
		$sequence_15 = { c705????????01000000 ff15???????? 8b1d???????? ffd3 8bf8 33f6 8bcf }
		$sequence_16 = { 648b1530000000 8b520c 8b521c 8b5a08 }
		$sequence_17 = { 8b430c 034510 6a04 6800100000 51 50 }
		$sequence_18 = { 8d7a08 e8???????? 52 e8???????? e9???????? 0fb755e0 83fa08 }
		$sequence_19 = { e8???????? b02c aa 8b4510 85c0 }
		$sequence_20 = { 33c0 f3aa eb10 e8???????? 8b4314 034508 }
		$sequence_21 = { 8b5324 f7c200000002 7412 6800400000 8b4310 50 }
		$sequence_22 = { e8???????? 0fb64de2 8b55ec 8b7df0 8b07 }
		$sequence_23 = { b940000000 50 e2fd 56 394510 747e }

	condition:
		7 of them and filesize <8224768
}