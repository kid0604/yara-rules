rule win_svcready_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.svcready."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.svcready"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8935???????? 834dfcff b9???????? e8???????? 8b4df4 5e }
		$sequence_1 = { 897710 53 894714 e8???????? 8b4508 83c40c c6043300 }
		$sequence_2 = { 83c032 89442440 8b44240c 89442444 8d0437 8944240c 8d0437 }
		$sequence_3 = { e8???????? 8365fc00 8bc6 837e1410 7202 8b06 ff75e8 }
		$sequence_4 = { 89742410 33c7 2305???????? 0bf3 23f1 8b4c2414 0bcb }
		$sequence_5 = { 33f0 33ca 8bfe 23ee f7d7 33e9 897c2414 }
		$sequence_6 = { e8???????? 8b742424 8d4c2438 33ff 837c244c10 56 }
		$sequence_7 = { 56 89442420 e8???????? 8b7c241c 83c40c 57 6a00 }
		$sequence_8 = { 8b5c2418 33f0 33f1 c1ca05 }
		$sequence_9 = { 59 8903 894304 03c7 894308 8975fc 8b0b }

	condition:
		7 of them and filesize <1187840
}
