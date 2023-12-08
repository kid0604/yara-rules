rule win_byeby_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.byeby."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.byeby"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 50 ffd6 c6840588feffff5c 8d458c 50 8d8588feffff 50 }
		$sequence_1 = { ff15???????? 8986c09b0110 83c604 83fe28 }
		$sequence_2 = { 85ff 7460 57 33f6 ffd3 85c0 7e15 }
		$sequence_3 = { c705????????18f50010 a3???????? c705????????a9f50010 c705????????03f60010 c705????????88f60010 }
		$sequence_4 = { c784242c0300005130394e c78424300300005455464f c684243403000000 c78424e402000056464a42 c78424e8020000546c4e47 c68424ec02000000 c784249c02000052566846 }
		$sequence_5 = { 8906 8bc6 c7460400000000 c7464000000000 c7464400000000 c7464800000000 c7464c00000000 }
		$sequence_6 = { 56 50 0fb785baf9ffff 50 }
		$sequence_7 = { 8d4c2430 e8???????? 6a38 8d442438 c78424040b000000000000 6a00 50 }
		$sequence_8 = { 83c8ff a3???????? eb0e a1???????? 83f8ff 0f850a030000 833d????????ff }
		$sequence_9 = { 83c40c c78424d40200005656424d 8d8424d4020000 c78424d802000054304645 c68424dc02000000 c78424e002000052453958 50 }

	condition:
		7 of them and filesize <253952
}
