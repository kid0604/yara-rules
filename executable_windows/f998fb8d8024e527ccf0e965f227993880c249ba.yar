rule win_iispy_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.iispy."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.iispy"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 5d c3 8d4305 8d4e01 83f805 777b b802000000 }
		$sequence_1 = { 837da800 6689700e 740b ff75ac e8???????? 83c404 6a01 }
		$sequence_2 = { 5d c3 5f 5b b80d000780 5e 8be5 }
		$sequence_3 = { 51 8bcf 89442414 e8???????? 8b37 }
		$sequence_4 = { 8d4de4 e8???????? 51 ff7614 8d4de4 e8???????? 837dec00 }
		$sequence_5 = { 0fb686c0820210 8807 0fb686c1820210 8b750c 8b7dec 8806 0fb6047dc0820210 }
		$sequence_6 = { 2b85b0f8ffff 898590f8ffff 0f859efcffff 8b8d7cf8ffff 85c9 0f840e050000 8b048d340a0210 }
		$sequence_7 = { 0fb6c9 894c2414 33c9 803830 8b442414 0f44c1 }
		$sequence_8 = { 8b442414 0f44c1 89442414 33ff 84c0 7464 }
		$sequence_9 = { 8d4dd8 56 e8???????? 8bc8 e8???????? 8d4dd8 }

	condition:
		7 of them and filesize <397312
}
