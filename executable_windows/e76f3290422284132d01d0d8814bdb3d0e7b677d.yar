rule win_darkvnc_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.darkvnc."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkvnc"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b442404 488b4c2420 0fb70441 83f825 752f 8b0424 b925000000 }
		$sequence_1 = { 48894130 8b4108 2b01 894138 7456 488b4328 }
		$sequence_2 = { 488b442478 4839842480000000 7417 4c8b842480000000 33d2 488b0d???????? ff15???????? }
		$sequence_3 = { 7406 ff15???????? 85db 7408 8bcb ff15???????? 488bc6 }
		$sequence_4 = { 498bf6 3b6efc 754a f70600000040 7430 e8???????? 83f805 }
		$sequence_5 = { 85db 755d 488b4df0 ff15???????? 8b4540 448bce 4c8b4530 }
		$sequence_6 = { 3bc7 74c3 488bcb e8???????? 85b3f0000000 754d ff15???????? }
		$sequence_7 = { 4585db 0f8e86000000 4c63742458 4963e8 498d041e 4c8be9 }
		$sequence_8 = { 750c 488b442438 4889442440 eb47 eb24 488b442428 488b00 }
		$sequence_9 = { 4883c020 4889442430 488b442430 83780400 0f849f000000 488b542440 488b442430 }

	condition:
		7 of them and filesize <606208
}
