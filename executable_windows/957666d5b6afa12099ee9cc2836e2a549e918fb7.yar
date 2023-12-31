rule win_screencap_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.screencap."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.screencap"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488b4c2450 488364242000 488d0591e90000 488b0cc8 4c8d4c2458 488d542460 498b0c0f }
		$sequence_1 = { 41c1eb05 418d5f01 41c1e302 83fe08 }
		$sequence_2 = { 4883ec20 4c8d25a09c0000 33f6 33db 498bfc 837f0801 7526 }
		$sequence_3 = { 39842420100000 0f869f010000 6a04 687c334700 55 e8???????? }
		$sequence_4 = { 488bce ff15???????? bf00080000 3bdf 7702 }
		$sequence_5 = { 72ed 48833d????????00 741f 488d0d06130100 e8???????? }
		$sequence_6 = { 8bdf e8???????? 85ff 741c 488d4c2450 0fb601 84c0 }
		$sequence_7 = { 3bf8 0f869c000000 6a04 687c334700 55 e8???????? }
		$sequence_8 = { 8d854c100000 50 ff15???????? 8bf0 8975e0 85f6 0f84bb030000 }
		$sequence_9 = { 89470c 894710 894714 8d854c2c0000 50 e8???????? 6805040000 }

	condition:
		7 of them and filesize <1391616
}
