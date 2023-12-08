rule win_nitol_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.nitol."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nitol"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d45d0 6a10 50 6a00 53 }
		$sequence_1 = { ff15???????? 83f801 75e8 6a00 ff15???????? 85c0 74dc }
		$sequence_2 = { 889df8fcffff 6a1f f3ab 66ab aa 59 33c0 }
		$sequence_3 = { ffb5e4feffff 8945e8 ff748dc4 50 ff15???????? }
		$sequence_4 = { 43 f7fb 8d85b0fdffff 50 }
		$sequence_5 = { ff7485c4 8d8560ffffff 68???????? 50 ff15???????? 83c410 }
		$sequence_6 = { ff15???????? 6800020000 8945dc 897de0 c645e450 c645e504 }
		$sequence_7 = { 0fafc6 f7742408 5e 8bc2 c3 ff742404 ff15???????? }
		$sequence_8 = { 48 48 7470 48 7447 }
		$sequence_9 = { 59 f7f9 80c230 eb0b ffd3 }

	condition:
		7 of them and filesize <139264
}
