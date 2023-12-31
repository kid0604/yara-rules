rule win_azov_wiper_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.azov_wiper."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.azov_wiper"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 4c8bc8 4885c0 7455 488d442440 }
		$sequence_1 = { 488d5201 6685c0 75ee 488b05???????? 488bcb 488b10 ff9250010000 }
		$sequence_2 = { 41ff9288010000 85c0 740f 4881c79a020000 4889bc2410030000 483bbc2418030000 0f8c73ffffff }
		$sequence_3 = { 48894c2440 4533c0 48898c2470080000 4c8b10 488d842470080000 }
		$sequence_4 = { 33d2 33c9 48897c2420 4c8b10 41ff92b0000000 8bce }
		$sequence_5 = { 4c8b00 41ff5058 85c0 0f84c6000000 4c89b42480000000 448d4b04 }
		$sequence_6 = { 488bcb 4c8b10 41ff9288010000 85c0 740f 4881c79a020000 }
		$sequence_7 = { 4883ec20 4080e4f0 c645f356 c645f469 c645f572 }
		$sequence_8 = { 488945f8 4883ec08 48890424 4883ec08 }
		$sequence_9 = { 0f8493000000 488bd0 488bcb 482bd3 }

	condition:
		7 of them and filesize <73728
}
