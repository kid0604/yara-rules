rule win_client_maximus_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.client_maximus."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.client_maximus"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 89f0 0fb6c0 0fb61403 88140b 83c101 89fa 81f900010000 }
		$sequence_1 = { 89e5 56 53 83ec10 8b1d???????? }
		$sequence_2 = { 893424 ff15???????? 83ec08 85c0 7411 }
		$sequence_3 = { e8???????? 8b4304 85c0 741d 8b5330 c744240800800000 c744240400000000 }
		$sequence_4 = { 39730c 7fe1 891424 e8???????? }
		$sequence_5 = { 7429 c70424???????? ff15???????? 83ec04 a3???????? }
		$sequence_6 = { 8b4628 85c0 7535 c70424???????? }
		$sequence_7 = { a3???????? c7442404???????? 893424 ff15???????? 83ec08 85c0 7411 }
		$sequence_8 = { 89c8 0fb63c0b 99 f77c241c 89f8 }
		$sequence_9 = { 89f8 02441500 01c6 89f0 0fb6c0 }

	condition:
		7 of them and filesize <106496
}
