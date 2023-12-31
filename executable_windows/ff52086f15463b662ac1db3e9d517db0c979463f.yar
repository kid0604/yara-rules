rule win_headertip_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.headertip."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.headertip"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c745f4c0d40100 ff15???????? 53 8d45f4 }
		$sequence_1 = { 57 57 ff761c e8???????? 59 59 }
		$sequence_2 = { 7462 817dfcc8000000 7559 33c0 }
		$sequence_3 = { 885dd7 c645ac47 c645ad65 c645ae74 c645af56 c645b06f c645b16c }
		$sequence_4 = { ffd0 85c0 7503 2145fc 8b45fc eb02 33c0 }
		$sequence_5 = { 750d ff36 ff15???????? 59 33c0 eb03 33c0 }
		$sequence_6 = { 8b4508 8808 8b450c 8a4df1 8808 8b45f4 8b4d14 }
		$sequence_7 = { c705????????50460000 ff15???????? ff35???????? ff15???????? 6817ca2b6e e8???????? 8bf0 }
		$sequence_8 = { 8d450f 50 e8???????? 83c410 }
		$sequence_9 = { 8b4114 2b410c 03c6 ebea 56 }

	condition:
		7 of them and filesize <174080
}
