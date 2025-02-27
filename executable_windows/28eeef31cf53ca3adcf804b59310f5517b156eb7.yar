rule win_roadsweep_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.roadsweep."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.roadsweep"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c1f902 0fb691b0914000 88141e 8b18 46 }
		$sequence_1 = { 8944240c 8b4514 89442404 ff521c 8b75c8 31c9 }
		$sequence_2 = { 85c0 740c 31c0 8b5df8 8b75fc 89ec 5d }
		$sequence_3 = { 7403 83cb01 84c9 7409 8b4d18 8b39 01f8 }
		$sequence_4 = { 5b 5e 5f 5d c3 85c0 750d }
		$sequence_5 = { 89e5 fc 83ec08 b90e000000 891c24 8b5d08 897c2404 }
		$sequence_6 = { 8b9540ffffff 891424 e8???????? c745a001000000 e8???????? 83c518 837da001 }
		$sequence_7 = { c744240400000000 83ee64 891c24 e8???????? }
		$sequence_8 = { c68565fdffff23 c68566fdffff5b c68567fdffff55 c68568fdffff7f c68569fdffff36 c6856afdffff7e c6856bfdffff76 }
		$sequence_9 = { 89542408 891c24 e8???????? 893424 e8???????? 8b4510 }

	condition:
		7 of them and filesize <160768
}
