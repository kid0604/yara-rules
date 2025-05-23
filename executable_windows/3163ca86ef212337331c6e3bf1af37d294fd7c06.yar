rule win_unidentified_106_auto_alt_2
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.unidentified_106."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_106"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 33c0 eb2a bdfdffffff 4d85e4 741e 4585ed }
		$sequence_1 = { f7d7 4881ffb057c96e 410fbff0 48bffd4d2301f6224375 488b7c2428 488b3f ff742408 }
		$sequence_2 = { c3 44886814 4c8d842480000000 8d4701 b20d 488bcb 6689842480000000 }
		$sequence_3 = { 8bc1 c1e810 884201 8bc1 c1e808 884202 c6020b }
		$sequence_4 = { e8???????? 448bf0 85c0 7410 488bcb e8???????? 418bc6 }
		$sequence_5 = { f20f59f1 f20f587330 0f28c6 f20f5c4328 660f2f4320 7612 4c8b4318 }
		$sequence_6 = { befdffffff e9???????? 4c8b642448 befeffffff 4c8b6c2428 e9???????? 4c8b642448 }
		$sequence_7 = { 498bcf e8???????? 85c0 0f8ef1000000 48837f5000 8b442434 894710 }
		$sequence_8 = { 48ffca 66c1e908 6685c9 75e3 418bf6 ff07 488b9c2428010000 }
		$sequence_9 = { e8???????? 488b9ed8000000 49c7c4ffffffff 44897d48 4c8be8 44897d50 4d8bf4 }

	condition:
		7 of them and filesize <27402240
}
