rule win_redshawl_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.redshawl."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redshawl"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ffc6 488d0c80 488d05baaa0000 488d0cc8 48890f ff15???????? 85c0 }
		$sequence_1 = { e8???????? 488b8b58010000 e8???????? 488d7b58 be06000000 488d0519c30000 483947f0 }
		$sequence_2 = { 488bce 488bc6 488d15709a0000 83e11f }
		$sequence_3 = { 488b8b58010000 e8???????? 488d7b58 be06000000 488d0519c30000 }
		$sequence_4 = { e9???????? 4c8d2552940000 488b0d???????? eb7c }
		$sequence_5 = { eb76 33c9 488d1543bb0000 48891401 4883c230 4883c108 48ffcb }
		$sequence_6 = { 8905???????? 8b430c 8905???????? 8bd7 4c8d0520d1ffff 89542420 }
		$sequence_7 = { 8bd8 488bcf ff15???????? 488b742438 8bc3 }
		$sequence_8 = { 72ed 48833d????????00 741f 488d0dc2c10000 e8???????? 85c0 }
		$sequence_9 = { 4c8d251ac70000 4863f8 49833cfc00 752b b900100000 }

	condition:
		7 of them and filesize <174080
}