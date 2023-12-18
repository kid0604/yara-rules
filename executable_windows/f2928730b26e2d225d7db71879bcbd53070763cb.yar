rule win_mqsttang_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.mqsttang."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mqsttang"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { f20f2ac0 f20f5905???????? 660f28c8 660f54ca 660f2ed9 7629 f20f58cb }
		$sequence_1 = { f0832801 8b85c0fdffff 0f845a010000 8b85b4fdffff 89780c 8b400c 85c0 }
		$sequence_2 = { e9???????? 89c7 89d9 89fb e8???????? 89f1 e8???????? }
		$sequence_3 = { ff5074 8b03 83ec04 89d9 8b707c ff5078 890424 }
		$sequence_4 = { e9???????? c74424240a030000 c744242001000000 e9???????? c74424240b030000 c744242000000000 e9???????? }
		$sequence_5 = { e8???????? e9???????? c744240405000000 c70424???????? e8???????? 8d5de4 8b4dd4 }
		$sequence_6 = { e8???????? 8d4c247c e8???????? 8d8c2480000000 e8???????? 8d8c2484000000 e8???????? }
		$sequence_7 = { f6040e10 7441 83c002 47 894338 39bdd8aeffff 77c7 }
		$sequence_8 = { f30f11442430 f20f115c2428 f30f11542420 f30f114c2418 e8???????? f20f106c2438 f20f105c2428 }
		$sequence_9 = { e9???????? c744240cffffffff c7442408???????? 89542404 03400c 890424 e8???????? }

	condition:
		7 of them and filesize <12651520
}
