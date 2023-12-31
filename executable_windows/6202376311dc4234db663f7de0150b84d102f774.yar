rule win_megumin_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.megumin."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.megumin"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b348510164600 037520 6b45243c 034528 6bc03c 03452c }
		$sequence_1 = { 8945e8 57 8d4dd8 c745fc00000000 e8???????? 8b45e8 85c0 }
		$sequence_2 = { 8d45f4 64a300000000 6841010000 8d8528faffff c745fc00000000 6a00 50 }
		$sequence_3 = { 8d4dd8 8d45c0 50 e8???????? ff37 8d55d7 8d4db0 }
		$sequence_4 = { c60100 e8???????? 8d4c2430 e8???????? 8bc8 83c418 83791410 }
		$sequence_5 = { 833d????????00 0f8549870000 8d0d90e74500 ba1d000000 e9???????? 833d????????00 0f852c870000 }
		$sequence_6 = { 83c404 8d8d14fdffff c645fc1a 51 8bd0 8d8d04fbffff }
		$sequence_7 = { 0f1f440000 8845eb 8b410c 897da8 8945b0 c645fc02 }
		$sequence_8 = { 8d4101 8945d8 3dffffff7f 0f8700010000 6a00 6a00 50 }
		$sequence_9 = { 3bca 763b 8bd1 a81f 7535 8b48fc }

	condition:
		7 of them and filesize <1007616
}
