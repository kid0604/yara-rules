rule win_graphical_neutrino_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.graphical_neutrino."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.graphical_neutrino"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 4889da e8???????? 488b442458 b950000000 4d8b742408 488b00 488b6808 }
		$sequence_1 = { e8???????? 85c0 7435 c605????????01 31c0 488b7c2438 8a1407 }
		$sequence_2 = { 53 4883ec28 31c0 803901 4889d5 7552 }
		$sequence_3 = { eb07 b001 80fa09 7478 }
		$sequence_4 = { 4889c1 e8???????? 48897308 4889d9 ba01000000 }
		$sequence_5 = { e8???????? 84c0 4c0f45e6 4c89e0 4883c428 5b 5e }
		$sequence_6 = { 7402 8a02 888424c1000000 b980000000 31c0 488dbc24c2000000 }
		$sequence_7 = { 4c89e9 488d7c2430 e8???????? 488b442450 4989442408 4839de 0f84bc000000 }
		$sequence_8 = { 7413 80fa02 742c 31c0 84d2 }
		$sequence_9 = { 48637c2428 8d743d00 39f7 7f2b 83fe0f }

	condition:
		7 of them and filesize <674816
}
