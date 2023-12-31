rule win_azorult_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.azorult."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.azorult"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6aff 68???????? 8b45f4 50 }
		$sequence_1 = { e8???????? 50 8b45dc e8???????? 50 e8???????? }
		$sequence_2 = { e8???????? 7458 8b55f8 8b45fc e8???????? 8bd8 }
		$sequence_3 = { e8???????? 33ff 33c0 8945f0 8b45fc }
		$sequence_4 = { 59 648910 68???????? 8d8584fdffff }
		$sequence_5 = { e8???????? 6aff 8b45d8 e8???????? }
		$sequence_6 = { c745f401000000 8d45ec 8b55fc 8b4df4 8a540aff e8???????? }
		$sequence_7 = { 33d2 e8???????? 7464 8b45f4 33d2 }
		$sequence_8 = { 53 e8???????? 59 56 e8???????? 59 8bc7 }
		$sequence_9 = { 7506 ff05???????? 56 e8???????? }
		$sequence_10 = { e8???????? 59 8b45f4 40 }
		$sequence_11 = { 50 e8???????? 59 8bd8 33c0 }
		$sequence_12 = { 85db 7404 8bc3 eb07 }
		$sequence_13 = { 014f18 8b4714 85c0 0f854e010000 }
		$sequence_14 = { 014110 5f 5e 5b }
		$sequence_15 = { 011f 59 8bc3 c1e003 01866caf0100 }

	condition:
		7 of them and filesize <1753088
}
