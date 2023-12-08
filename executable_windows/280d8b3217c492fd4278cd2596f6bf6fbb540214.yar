rule win_icefog_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.icefog."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icefog"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 894df0 e8???????? 8b4e70 8bf8 894648 33c0 03cf }
		$sequence_1 = { 8b0e 8d55ec 52 50 51 53 e8???????? }
		$sequence_2 = { 894614 8b4310 8d7e04 57 0d00010000 50 68d0070000 }
		$sequence_3 = { eb16 53 57 e8???????? 50 8b4508 50 }
		$sequence_4 = { 8955cc 8b45dc 8b55d8 894324 83c8ff 894308 894304 }
		$sequence_5 = { 8d84245c0c0000 50 ff15???????? 83c40c eb2b 8d8c246e080000 51 }
		$sequence_6 = { 6af1 52 6a00 6a00 6a00 6885000000 56 }
		$sequence_7 = { e8???????? 8b4e18 8b5508 894510 8d45d8 50 51 }
		$sequence_8 = { 7205 83f97f 7708 b801000000 5e 5d c3 }
		$sequence_9 = { 8d9558ffffff 52 8bc3 c745b400000000 e8???????? 83c404 8945d0 }

	condition:
		7 of them and filesize <1187840
}
