rule win_xfilesstealer_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.xfilesstealer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xfilesstealer"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ffd3 33c9 85c0 7524 448b4c2450 4c8d05c3f12600 ba00040000 }
		$sequence_1 = { e8???????? 8bf8 488d4dc0 e8???????? 85ff 0f88cb000000 488d55c0 }
		$sequence_2 = { ffd3 498b4f58 894114 498b4758 33ff 897818 498b4758 }
		$sequence_3 = { eb00 90 488d4d48 e8???????? 90 837d5800 7411 }
		$sequence_4 = { e8???????? 4c392b 7439 488b05???????? 488906 488d0d439c8900 48894e08 }
		$sequence_5 = { ffd3 4c63c0 48c744243080060000 4c89442428 48c744242020205248 4c8d0dee771b00 ba00400000 }
		$sequence_6 = { b801000000 e9???????? 85ed 7512 4d8bc6 488bd6 488bcb }
		$sequence_7 = { ff15???????? 8bd8 85c0 7e09 0fb7d8 81cb00000780 488d4db0 }
		$sequence_8 = { 89742428 4489742420 4c8d4df8 4c8d45d8 488b55f0 488d8d30010000 e8???????? }
		$sequence_9 = { ff5208 33c0 4883c448 c3 488d4c2420 c744242890010000 e8???????? }

	condition:
		7 of them and filesize <20821780
}