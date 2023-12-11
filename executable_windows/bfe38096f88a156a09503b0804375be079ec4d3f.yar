rule win_blackbasta_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.blackbasta."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackbasta"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { b8ffffff7f 8bd1 d1ea 2bc2 57 3bc8 7607 }
		$sequence_1 = { 6800000080 ff15???????? 85c0 754d 837d1c08 8d4d08 }
		$sequence_2 = { c745bc0f000000 884da8 8b03 c745fc04000000 8b702c 8d8560ffffff }
		$sequence_3 = { 8bec 83ec14 56 8b7508 ff34b5bc430a10 e8???????? 50 }
		$sequence_4 = { 83453040 41 8345340c 8b7d4c 8b5550 894d0c 85ff }
		$sequence_5 = { 8945ec 57 ff7508 ff7704 ff37 e8???????? 83c410 }
		$sequence_6 = { 0540420f00 8945ec 83d100 894de8 eb14 c745ecffffffff }
		$sequence_7 = { 64a100000000 50 64892500000000 83ec34 56 57 8d45c0 }
		$sequence_8 = { 6a00 53 51 8bcf ff501c 5f 5e }
		$sequence_9 = { c645b400 3b35???????? 740f ff7620 e8???????? 83c404 8bd0 }

	condition:
		7 of them and filesize <1758208
}
