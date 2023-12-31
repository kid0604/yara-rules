rule win_volgmer_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.volgmer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.volgmer"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488b4d40 4833cc e8???????? 4c8d9c2450010000 498b5b18 498b7b20 498be3 }
		$sequence_1 = { 48897c2418 55 488d6c24b0 4881ec50010000 488b05???????? 4833c4 }
		$sequence_2 = { e8???????? 8905???????? 85c0 7543 488b7c2440 }
		$sequence_3 = { ff15???????? 448b4c2440 48895c2438 488d442448 }
		$sequence_4 = { 024c1420 0fb6c1 0fb64c0420 304bff 4983ea01 75a9 488b4d40 }
		$sequence_5 = { e9???????? 4889b42458050000 4c89a42418050000 488d8df0020000 }
		$sequence_6 = { e9???????? 48899c2498020000 488b5908 33d2 488d4c2440 41b808020000 4183f902 }
		$sequence_7 = { 488d8d70040000 488bf3 482bf1 0f1f4000 66660f1f840000000000 448b45d8 }
		$sequence_8 = { eb50 e8???????? 4533db 488d442440 }
		$sequence_9 = { d1c6 c1c105 03c6 89742404 03c3 }
		$sequence_10 = { 90 807c100100 488d5201 75f5 8d4201 668903 }
		$sequence_11 = { 772f b92c010000 ff15???????? 498b4d18 4c8bce 4c897c2430 }
		$sequence_12 = { e8???????? e8???????? e8???????? c705????????04000000 }
		$sequence_13 = { 7320 85ff 7e1c 8b742440 4533c9 e9???????? }
		$sequence_14 = { 488d8d30110000 e8???????? 8bd7 c6843d3011000000 488d8d30110000 }
		$sequence_15 = { 3c9f 3da43dab3d b13d cd3d }
		$sequence_16 = { ff7508 8d83200c0000 50 e8???????? 33db }
		$sequence_17 = { 6888210000 50 8d856cdaffff 50 8d8b200c0000 }
		$sequence_18 = { 83e63f c1f906 6bf630 8b0c8d80f16e00 80643128fd }
		$sequence_19 = { 397310 b850000000 b9bb010000 0f45c1 89831c0c0000 eb15 }
		$sequence_20 = { 8bd7 c1fa06 8bc7 83e03f 6bc830 8b049580f16e00 f644082801 }
		$sequence_21 = { 8b4048 f00fc118 4b 7515 8b45fc 817848b8e46e00 }
		$sequence_22 = { 8bd6 8bd8 899df0f3ffff 8d4201 0f1f00 8a0a }
		$sequence_23 = { ebc6 c745e0e8ba6e00 e9???????? c745e0f0ba6e00 e9???????? c745e0f8ba6e00 e9???????? }
		$sequence_24 = { 0f8530190000 8d0d90b86e00 ba1b000000 e8???????? }
		$sequence_25 = { 837e0c00 8bf8 0f84f7030000 8d8618030000 50 }
		$sequence_26 = { 50 e8???????? 6a00 6a00 8d8c2484000000 6a32 }
		$sequence_27 = { c6442425b8 c64424267c c64424278d c6442429c1 c644242bff c644242c99 c644242d21 }
		$sequence_28 = { 8bfb be1e000000 f3ab 8b4c2454 8d431c 894b04 }
		$sequence_29 = { eb7c c745e0e0ba6e00 ebbb d9e8 8b4510 dd18 }
		$sequence_30 = { 8d3c85c8f47300 8b0f 85c9 740b 8d4101 f7d8 }
		$sequence_31 = { 50 03fb 897c2420 e8???????? 8b0d???????? 83c410 a3???????? }
		$sequence_32 = { 50 8b85a4f8ffff 0fb7048534976e00 8d0485308e6e00 50 8d8590faffff }
		$sequence_33 = { 59 83cfff 897de4 8365fc00 8b049d80f17300 }
		$sequence_34 = { 3bf5 7554 8b742414 6aff 56 }
		$sequence_35 = { c745e0e0ba6e00 e9???????? 83e80f 7451 }
		$sequence_36 = { 7448 8d8c2488040000 8d542460 51 52 e8???????? 83c408 }

	condition:
		7 of them and filesize <393216
}
