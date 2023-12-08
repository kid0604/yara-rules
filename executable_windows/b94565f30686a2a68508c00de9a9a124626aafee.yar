rule win_disttrack_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.disttrack."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.disttrack"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 68???????? ff15???????? 8d45dc 50 ff15???????? 8b4ddc }
		$sequence_1 = { 57 e8???????? 6a07 e8???????? 59 c3 6a10 }
		$sequence_2 = { 58 5e 5d c3 6a0c 68???????? }
		$sequence_3 = { 52 6a00 6a00 6848000700 }
		$sequence_4 = { 83c404 50 e8???????? 83c404 68???????? ff15???????? }
		$sequence_5 = { ff15???????? 5d 5b 8bc7 5f 5e }
		$sequence_6 = { 53 53 56 52 ff15???????? 56 }
		$sequence_7 = { 0f84a0010000 8da42400000000 8b4508 0fb610 ff4d0c 885435fc 8a55fd }
		$sequence_8 = { 8b45cc 2b45c8 d1f8 8945c0 }
		$sequence_9 = { 83c40c c745f000000000 8da42400000000 8b45f0 8a4c05f8 8d5d0c }
		$sequence_10 = { e8???????? c745fcffffffff 8b5790 8b4204 c7443890d42a4200 }
		$sequence_11 = { e8???????? 488d1dae690100 488bcb e8???????? 488bcf 448bc0 }
		$sequence_12 = { 4c8d1d41450100 4c895c2428 488d158db20100 488d4c2428 e8???????? cc }
		$sequence_13 = { 8906 e8???????? 53 8d4d90 8bf8 e8???????? }
		$sequence_14 = { c78424a800000058c24100 e8???????? 83c404 8b442428 40 89442428 83f801 }
		$sequence_15 = { 8bc3 5f 8be5 5d c20400 8a470c 38460c }
		$sequence_16 = { 4503c0 e8???????? 8bd0 498d0c52 488bd3 e8???????? }
		$sequence_17 = { 53 8975f4 e8???????? 53 8bf8 56 }
		$sequence_18 = { 8b55b4 83c202 8955b4 66837dae00 }
		$sequence_19 = { 488d0dfa630100 e8???????? cc 48397918 730e }
		$sequence_20 = { 488d0d235f0100 488b04c1 41f644070840 740b 41807d001a 0f8432f9ffff }
		$sequence_21 = { 2bce 51 6a00 ff15???????? 8945ec 85c0 7449 }
		$sequence_22 = { 498bcd e8???????? 488d0dee590100 83c003 66897445e0 e8???????? 488d4de0 }
		$sequence_23 = { be???????? 0fb6c9 8a0431 88443b01 a1???????? b910000000 390d???????? }
		$sequence_24 = { 33ff 48897c2438 48897c2440 48897c2448 488d05982d0100 4889442430 488d542430 }
		$sequence_25 = { 8bd9 488d0dc5be0000 ff15???????? 4885c0 7419 488d15a3be0000 488bc8 }

	condition:
		7 of them and filesize <1112064
}
