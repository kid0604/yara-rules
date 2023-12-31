rule win_cameleon_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.cameleon."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cameleon"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 53 56 57 8bf9 897df0 c745ec00000000 8b07 }
		$sequence_1 = { 8a80f8c70410 8807 47 46 8bcb c6458301 e8???????? }
		$sequence_2 = { 83ec18 8bd4 8965ec c7421000000000 c7421400000000 }
		$sequence_3 = { 8d7dd0 837de408 0f437dd0 83ec18 8bd4 c7421000000000 c7421400000000 }
		$sequence_4 = { 48 a3???????? ff15???????? 8b0d???????? 89048d98ce0510 5d c3 }
		$sequence_5 = { 247f 88441628 eb12 0c80 88441628 8b0cbd50d60510 c644112900 }
		$sequence_6 = { b83b000000 663bc8 0f94c0 84c0 7431 }
		$sequence_7 = { 8d55dc c645fc02 8d8d24ffffff e8???????? 8bc8 8b01 }
		$sequence_8 = { 8bd9 56 57 837b3800 0f848c010000 807b3d00 0f8482010000 }
		$sequence_9 = { 5d c20400 85ff 75d4 897e10 837e1408 720f }

	condition:
		7 of them and filesize <824320
}
