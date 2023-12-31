rule win_flawedgrace_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.flawedgrace."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.flawedgrace"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c68583dcffff00 c68584dcfffffb c68585dcffff04 c68586dcffff56 c68587dcffff69 c68588dcffff72 c68589dcffff74 }
		$sequence_1 = { 8b4a1c 8bc1 c1e808 0fb6f0 8bc1 c1e810 0fb6f9 }
		$sequence_2 = { c685c7f6ffff00 c685c8f6ffff6c c685c9f6ffff21 c685caf6ffff00 c685cbf6ffff00 c685ccf6ffff7e c685cdf6ffff21 }
		$sequence_3 = { c6851ccbffffbd c6851dcbffffb0 c6851ecbfffffd c6851fcbffffff c68520cbffffff c68521cbffff48 c68522cbffff83 }
		$sequence_4 = { 897508 0f1002 0f1106 f30f7e4210 660fd64610 8b4e08 85c9 }
		$sequence_5 = { c6859cc8ffff01 c6859dc8ffff00 c6859ec8ffff00 c6859fc8ffff48 c685a0c8ffff83 c685a1c8ffffec c685a2c8ffff20 }
		$sequence_6 = { 83c410 83f81b eb2f 8d442454 660fd6442454 50 8b4708 }
		$sequence_7 = { 6a00 ffd6 8983a8020000 8db3d8020000 c645fc03 56 8975e0 }
		$sequence_8 = { 83854cc0ffff02 80bda7c0ffff00 75ae c785c8bfffff00000000 eb0b 1bc9 83c901 }
		$sequence_9 = { 50 56 ff15???????? 8bf8 56 ff15???????? 8bc7 }

	condition:
		7 of them and filesize <966656
}
