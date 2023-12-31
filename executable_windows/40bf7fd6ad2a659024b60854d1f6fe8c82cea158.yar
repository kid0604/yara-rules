rule win_sagerunex_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.sagerunex."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sagerunex"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488d542428 488d4c2428 4d8bc1 e8???????? 448b6c2428 85c0 8bd8 }
		$sequence_1 = { 8d040a 418bd4 4403f8 418bc4 418bc9 c1c00d c1c20f }
		$sequence_2 = { 8b742428 c1e803 23ce 33e8 418d0410 448b8424a0000000 03e8 }
		$sequence_3 = { 488bac2450060000 498bcf 85c0 740c e8???????? b886ffffff eb07 }
		$sequence_4 = { 7427 4c8b5b10 4c8d542448 498b44cbf8 4d8b44caf8 493bc0 0f87c2000000 }
		$sequence_5 = { 33d0 c1c10e 418bc6 41c1ee03 c1c807 33c8 }
		$sequence_6 = { 493bc4 7735 4d85e4 74d1 498d4424ff 492bd0 498d04c0 }
		$sequence_7 = { 498bd5 4885c0 7411 0f1f440000 c60200 488d5201 48ffc8 }
		$sequence_8 = { 33c8 418bc0 4123c1 440bd0 8d040a 8b4c240c 4403d0 }
		$sequence_9 = { 488bd9 488d0515080100 488981a0000000 83611000 c7411c01000000 c781c800000001000000 b843000000 }

	condition:
		7 of them and filesize <619520
}
