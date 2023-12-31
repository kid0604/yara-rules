rule win_htbot_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.htbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.htbot"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b7c2434 33db 8d74243c e8???????? 3bfb 8b4c2430 8919 }
		$sequence_1 = { ff15???????? 89442408 85c0 8b44240c 7527 8b4c2404 6a04 }
		$sequence_2 = { 8b41f4 8b0b 8b51f4 03c7 3bc6 0f8cdf000000 3bc2 }
		$sequence_3 = { e9???????? 8a4603 3c01 7550 83fd0a 0f8c07010000 8b7e04 }
		$sequence_4 = { 8b01 8b5004 55 ffd2 8b442428 8b8c2448100000 }
		$sequence_5 = { 8b8c2438040000 33cc e8???????? 81c448040000 c3 6857000780 }
		$sequence_6 = { c644242c04 e8???????? 8d542418 56 52 8bc8 c644243405 }
		$sequence_7 = { 895d00 e8???????? 6a00 6a00 }
		$sequence_8 = { 83c410 c64424640b 8b08 8b37 8d41f0 83ee10 }
		$sequence_9 = { 50 e8???????? 83c408 85c0 0f8439010000 2b03 83f8ff }

	condition:
		7 of them and filesize <196608
}
