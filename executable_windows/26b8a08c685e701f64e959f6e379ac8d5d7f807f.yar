rule win_laziok_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.laziok."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.laziok"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? c6043800 8bc7 5f 5e 5d }
		$sequence_1 = { 46 56 e8???????? 59 8b4c240c }
		$sequence_2 = { 8d44240c 50 51 68ffffff1f 52 }
		$sequence_3 = { 56 83c028 50 e8???????? 59 59 }
		$sequence_4 = { 68???????? 6a10 6a04 e8???????? 68???????? }
		$sequence_5 = { 6a00 6a00 ff15???????? c6043800 }
		$sequence_6 = { 33f6 e8???????? 59 59 85c0 740a }
		$sequence_7 = { ff7608 ff15???????? 8b460c 56 85c0 }

	condition:
		7 of them and filesize <688128
}
