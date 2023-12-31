rule win_govrat_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.govrat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.govrat"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7725 0fb74002 8d709f 6683fe19 7702 03c2 6685c0 }
		$sequence_1 = { ff37 e8???????? 894620 85c0 7507 b80e000780 5f }
		$sequence_2 = { e8???????? 83ec1c 8bf4 8965b4 }
		$sequence_3 = { e8???????? 6aff 53 8d4db0 51 c645fc06 e8???????? }
		$sequence_4 = { 837dc808 8b75b4 7303 8d75b4 53 51 68???????? }
		$sequence_5 = { 8d7c2428 ab ab 7548 8d442464 50 }
		$sequence_6 = { 0183f0bc0300 8393f4bc030000 e8???????? eb1d 8b45fc 2b45f0 ff75fc }
		$sequence_7 = { 7311 c70485????????e8814300 40 a3???????? c3 55 8bec }
		$sequence_8 = { 83ec18 56 8bf1 8b4610 8955f8 8945f4 83f804 }
		$sequence_9 = { 85f6 7403 832600 837d1000 0f8690000000 8b5d08 }

	condition:
		7 of them and filesize <761856
}
