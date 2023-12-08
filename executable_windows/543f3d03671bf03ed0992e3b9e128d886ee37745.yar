rule win_expiro_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.expiro."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.expiro"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 52 e8???????? 83c404 385c2413 0f85ddfdffff b8???????? 8d4c2414 }
		$sequence_1 = { e8???????? 83f8ff 741d 6a00 83c8ff b9???????? }
		$sequence_2 = { 7403 50 ffd6 8b442428 3bc3 7407 }
		$sequence_3 = { 50 e8???????? 83c404 b8???????? 8d4c2430 e8???????? }
		$sequence_4 = { 8d742430 8bf8 e8???????? 85ff 752c 8b542414 }
		$sequence_5 = { 83c40c c68424180900000f 395814 7204 8b10 eb02 8bd0 }
		$sequence_6 = { 8b8c2448080000 33cc e8???????? 81c450080000 c3 ff15???????? 8d54240c }
		$sequence_7 = { 5b 8b8c2448080000 33cc e8???????? 81c450080000 c3 ff15???????? }
		$sequence_8 = { 7407 50 ff15???????? 8ac3 e9???????? 57 ff15???????? }
		$sequence_9 = { 8b742420 68???????? e8???????? 8b442424 83c404 50 ff15???????? }

	condition:
		7 of them and filesize <3776512
}
