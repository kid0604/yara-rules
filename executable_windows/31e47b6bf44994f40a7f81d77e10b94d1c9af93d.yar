rule win_h1n1_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.h1n1."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.h1n1"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff7508 56 ff35???????? 58 ffd0 0bc0 750a }
		$sequence_1 = { ff75fc ff75f8 ff35???????? 58 }
		$sequence_2 = { 2d8eff8aff ab 351c001400 ab 0505009fff }
		$sequence_3 = { 51 6a15 ff7508 ff35???????? }
		$sequence_4 = { 51 52 b950c30000 0f31 }
		$sequence_5 = { ab ff75fc ff35???????? 58 ffd0 85c0 }
		$sequence_6 = { 0bc0 7423 8d45f8 50 ff75fc 6802000080 ff35???????? }
		$sequence_7 = { 6a00 6a15 ff75fc 6a00 }
		$sequence_8 = { c3 56 8b742408 6804010000 68f8820010 8d86f8020000 50 }
		$sequence_9 = { d1e9 330c8500850010 330c95f48b0010 42 890c95bc850010 81fae3000000 }
		$sequence_10 = { 8b048500850010 338774fcffff 33c1 8907 83c704 81ff7c8f0010 7cd4 }
		$sequence_11 = { f644242c01 55 50 6808850010 ff74242c b9686e0010 }
		$sequence_12 = { 6a13 b86c6e0010 59 ff742428 }
		$sequence_13 = { 50 8d8578fdffff 50 68fc600010 6804010000 }
		$sequence_14 = { 5b 8bc1 83e001 d1e9 330c8500850010 330d???????? 890d???????? }
		$sequence_15 = { 50 ffb610850010 57 ff15???????? 83c608 83fe18 72e2 }

	condition:
		7 of them and filesize <172032
}
