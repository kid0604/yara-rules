rule win_plugx_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.plugx."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.plugx"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 51 56 57 6a1c 8bf8 e8???????? 8bf0 }
		$sequence_1 = { 41 3bca 7ce0 3bca }
		$sequence_2 = { 56 8b750c 8b4604 050070ffff }
		$sequence_3 = { 33d2 f7f3 33d2 8945fc }
		$sequence_4 = { 55 8bec 8b450c 81780402700000 }
		$sequence_5 = { 51 53 6a00 6a00 6a02 ffd0 85c0 }
		$sequence_6 = { 0145f4 8b45fc 0fafc3 33d2 }
		$sequence_7 = { 50 ff15???????? a3???????? 8b4d18 }
		$sequence_8 = { e8???????? 3de5030000 7407 e8???????? }
		$sequence_9 = { e8???????? 85c0 7508 e8???????? 8945fc }
		$sequence_10 = { 85c0 7413 e8???????? 3de5030000 }
		$sequence_11 = { e8???????? 85c0 7407 b84f050000 }
		$sequence_12 = { 6a00 6a00 6a04 6a00 6a01 6800000040 57 }
		$sequence_13 = { e8???????? 85c0 750a e8???????? 8945fc }
		$sequence_14 = { 85c0 750d e8???????? 8945f4 }
		$sequence_15 = { 51 6a00 6800100000 6800100000 68ff000000 6a00 6803000040 }
		$sequence_16 = { 6819000200 6a00 6a00 6a00 51 }
		$sequence_17 = { 57 e8???????? eb0c e8???????? }
		$sequence_18 = { 81ec90010000 e8???????? e8???????? e8???????? }
		$sequence_19 = { 68???????? e8???????? 6800080000 68???????? e8???????? }
		$sequence_20 = { 50 56 ffb42480000000 ff15???????? }
		$sequence_21 = { 89742434 89f1 8b442434 e8???????? }
		$sequence_22 = { 89442424 8b442424 6808020000 6a00 }
		$sequence_23 = { 6a02 6a00 e8???????? c705????????00000000 }
		$sequence_24 = { 5d c21000 55 53 57 56 83ec18 }
		$sequence_25 = { 6a00 6a00 6a01 6a00 e8???????? a3???????? 6800080000 }
		$sequence_26 = { 6808020000 6a00 ff74242c e8???????? 83c40c }
		$sequence_27 = { 50 ff75e8 6802000080 e8???????? }
		$sequence_28 = { 50 6802000080 53 e8???????? }
		$sequence_29 = { 68000000a0 6aff ffb424c8000000 ff74241c }
		$sequence_30 = { 6808020000 6a00 ff74245c e8???????? }
		$sequence_31 = { 6a5c ff74241c e8???????? 83c408 }
		$sequence_32 = { 5e 5f 5b 5d c20400 50 64a118000000 }

	condition:
		7 of them and filesize <1284096
}
