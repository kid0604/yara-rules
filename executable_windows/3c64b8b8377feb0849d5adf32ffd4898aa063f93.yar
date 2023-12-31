rule win_equationdrug_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.equationdrug."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.equationdrug"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b442440 bd04000000 03cd 48 894c2420 89442440 740a }
		$sequence_1 = { 52 66894c2408 ff15???????? 33c9 5e 85c0 0f9dc1 }
		$sequence_2 = { 7505 be1a030000 8d4c2414 c7442454ffffffff e8???????? 8bc6 e9???????? }
		$sequence_3 = { 0f850e010000 8bcf e8???????? 8b542410 8bca 81e1ffff0000 c1e109 }
		$sequence_4 = { 03d1 83fa10 0f8fb3fdffff 8b5c2440 8b7c2448 8d83a0000000 3bd8 }
		$sequence_5 = { 8b442428 8bcf c1e109 03c8 8b44241c 56 51 }
		$sequence_6 = { 8bca 83e103 f3a4 8b4d20 66894524 c6041900 33c0 }
		$sequence_7 = { c1fa03 3bca 0f8386000000 8b1cc8 84db 8b44c804 895c2414 }
		$sequence_8 = { 8bc8 83e103 f3a4 8b742410 8bcd 56 53 }
		$sequence_9 = { eb64 8d4c244c e8???????? 50 8d8c2490000000 e8???????? }

	condition:
		7 of them and filesize <449536
}
