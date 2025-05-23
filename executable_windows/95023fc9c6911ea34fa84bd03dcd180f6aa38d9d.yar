rule win_arik_keylogger_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.arik_keylogger."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.arik_keylogger"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b8064040000 85c0 7468 8b45fc 8b8064040000 e8???????? 89c3 }
		$sequence_1 = { ff4008 8b45fc ff40f0 e8???????? 8d45c0 e8???????? c745c000000000 }
		$sequence_2 = { 8d85fcfdffff 89da e8???????? 85c0 750c c745fc12000000 e9???????? }
		$sequence_3 = { 8d9574ffffff b801000000 e8???????? e8???????? 50 85c0 0f8576010000 }
		$sequence_4 = { ff75f0 a1???????? ffd0 8b45f4 83c060 b100 ba10000000 }
		$sequence_5 = { c3 55 89e5 83ec04 a1???????? 8945fc 8b45fc }
		$sequence_6 = { c745f800000000 58 85c0 7405 e8???????? 8b5dc8 8b75cc }
		$sequence_7 = { 8b85b8feffff 8945f0 e8???????? 89c3 8d55e8 89d8 8b0b }
		$sequence_8 = { 8b8064040000 8945f4 8b45fc 8b407c 85c0 7434 814df800000200 }
		$sequence_9 = { eb60 8b45fc 8b40fc 8b4060 ff30 8b45fc 8b40fc }

	condition:
		7 of them and filesize <4947968
}
