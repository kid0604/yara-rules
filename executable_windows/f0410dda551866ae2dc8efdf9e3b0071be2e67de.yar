rule win_tabmsgsql_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.tabmsgsql."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tabmsgsql"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 64892500000000 81ec18020000 53 56 57 33db b97f000000 }
		$sequence_1 = { 0f84fb000000 83faff 0f84f2000000 bf???????? 83c9ff 33c0 }
		$sequence_2 = { 5f 5e 5d 5b 7421 8b8424f8f40100 }
		$sequence_3 = { 3bfa 7536 fec8 8841ff 895304 }
		$sequence_4 = { 83d8ff 85c0 741b 57 8d442414 68???????? 50 }
		$sequence_5 = { 8d45dc 68???????? 50 8d8dc8f7ffff 68???????? 51 ffd6 }
		$sequence_6 = { 33c0 83c424 f2ae f7d1 49 5f 81f9a0860100 }
		$sequence_7 = { 6a00 8d55dc 6a00 52 8d85940bfeff }
		$sequence_8 = { 50 51 6a00 ff15???????? 85c0 7430 8d7c241c }
		$sequence_9 = { 33c0 68???????? f2ae f7d1 2bf9 8d442434 8bd1 }

	condition:
		7 of them and filesize <163840
}
