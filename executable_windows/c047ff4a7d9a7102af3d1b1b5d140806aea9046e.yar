rule win_romeos_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.romeos."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.romeos"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a16 8d4c244c 6800200000 51 57 }
		$sequence_1 = { 50 bd30000000 e8???????? 8bbc2454200000 83c404 8bce 50 }
		$sequence_2 = { 55 52 57 8bce e8???????? 85c0 }
		$sequence_3 = { eb2b b141 663d14c0 884c2414 7506 b161 }
		$sequence_4 = { 8b542414 6a16 8d44244c 52 }
		$sequence_5 = { 85c0 754c 6a16 8d54241c 55 }
		$sequence_6 = { 5e 5d 5b 81c438200000 c20400 }
		$sequence_7 = { 88441c18 43 3bdd 7cf2 8b542414 }
		$sequence_8 = { ffd6 8d4c2420 8944241c 51 }
		$sequence_9 = { c3 3bfb 0f8d8e000000 8b2d???????? 6a01 }
		$sequence_10 = { c1ea18 33c3 8b1c9520fc0010 8b56fc 33c3 8b1c8d20080110 }
		$sequence_11 = { 837c240cff 7460 8b07 8d4c2412 51 6a01 }
		$sequence_12 = { a3???????? 8b6c241c 3beb 741a 6830560110 }
		$sequence_13 = { 7513 8b4c2410 53 51 53 53 }
		$sequence_14 = { ff15???????? 47 3bfd 0f8c4cffffff 8bce e8???????? 5f }
		$sequence_15 = { 8d4c2418 50 51 8bcf c744241800000000 c744241c03010000 }

	condition:
		7 of them and filesize <294912
}
