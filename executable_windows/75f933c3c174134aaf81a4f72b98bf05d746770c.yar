rule win_dratzarus_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.dratzarus."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dratzarus"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488d8d12040000 33d2 41b8260a0000 66899d10040000 e8???????? 8d4b40 ba00200300 }
		$sequence_1 = { 418b400c 418b4810 418b5014 458bca 0f1f440000 0bc1 0bca }
		$sequence_2 = { eb69 01bbccaf0600 8b8bccaf0600 4c8d0524b20100 0fb69419b8af0100 8d4101 488bcb }
		$sequence_3 = { 2b756f 81fe50140000 0f8f8b030000 81feb0ebffff 0f8c6f030000 4c8d2d0ecc0000 4983ed60 }
		$sequence_4 = { 4885db 744e 448d4208 488d156e370100 488bcb e8???????? 85c0 }
		$sequence_5 = { 4c8d0504bf0100 e8???????? 81fd1e010000 7f0e 83fb1e 7f09 83fe13 }
		$sequence_6 = { 6685c0 75e7 488d8dc0280000 ba04010000 ff15???????? 4c8d8df0260000 4c8d85c0280000 }
		$sequence_7 = { 488d3d3a280200 4c8d442450 48f7d1 488d542458 48897c2420 48ffc9 }
		$sequence_8 = { 72ce 48215c2420 488d8520060000 448bc6 442bc0 488b442450 488d0da3b80400 }
		$sequence_9 = { 488bd0 ff15???????? 488d4c2420 ba07000000 488905???????? e8???????? }

	condition:
		7 of them and filesize <905216
}
