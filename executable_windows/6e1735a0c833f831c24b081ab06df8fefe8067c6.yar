rule win_rikamanu_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.rikamanu."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rikamanu"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 6a14 ff15???????? a801 }
		$sequence_1 = { 50 ff15???????? 8b35???????? 3d80969800 }
		$sequence_2 = { 33c0 663bcb 0f95c0 a3???????? }
		$sequence_3 = { 80c120 888820ad4000 eb1f 83f861 7213 83f87a 770e }
		$sequence_4 = { 59 50 8d85e8faffff 50 ff35???????? }
		$sequence_5 = { 85f6 7419 0fb6da f683a1a7400004 }
		$sequence_6 = { c3 0fb6442404 8a4c240c 8488a1a74000 751c 837c240800 }
		$sequence_7 = { 8d8de4fdffff 51 e8???????? 8b8de4fdffff 8b35???????? 8d95ccfdffff }
		$sequence_8 = { 8d74242c b8???????? 8a10 8aca 3a16 751c 3acb }
		$sequence_9 = { 8b7d0c 85db 0f84b2000000 85ff 0f84aa000000 8d85a4fdffff }
		$sequence_10 = { 8bc3 8bcb c1f805 83e11f 8b0485e0b84000 }
		$sequence_11 = { 85c0 7457 68???????? 56 ffd5 }
		$sequence_12 = { 6810270000 ff15???????? 8b85e4fdffff 8d8dccfdffff 51 8d9588fdffff 52 }
		$sequence_13 = { 5d c20800 8b55e8 6a00 }
		$sequence_14 = { 888808972400 40 ebe6 ff35???????? ff15???????? 85c0 }
		$sequence_15 = { 8dbc2430010000 83c9ff f2ae f7d1 2bf9 8bf7 }
		$sequence_16 = { ffd3 55 55 8d4c2444 55 }
		$sequence_17 = { ff15???????? a3???????? 3bc3 7530 }
		$sequence_18 = { 8b35???????? 68???????? ffd6 8be8 83fdff 750b }
		$sequence_19 = { 6a00 68???????? 8b442418 6a03 }
		$sequence_20 = { 0fb6da f683a1a7400004 7406 8816 }
		$sequence_21 = { 7373 8bc8 8bf0 c1f905 83e61f 8d3c8de0b84000 c1e603 }
		$sequence_22 = { 8a8160204100 8802 5b 5d c3 }
		$sequence_23 = { a1???????? 0f45c6 a3???????? ebcf 83f802 }
		$sequence_24 = { 50 53 6800130000 ff15???????? 5b }
		$sequence_25 = { f682a1a7400004 740c ff01 85f6 }
		$sequence_26 = { 52 6a01 53 53 e8???????? 8b95e0fdffff }
		$sequence_27 = { 7410 8088????????20 8a9405ecfcffff ebe3 80a020ad400000 40 }
		$sequence_28 = { 68???????? e8???????? 8b3d???????? 59 59 85c0 751b }
		$sequence_29 = { 8d8914982400 5a 668b31 668930 }

	condition:
		7 of them and filesize <212992
}
