rule win_trochilus_rat_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.trochilus_rat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.trochilus_rat"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { bb00010000 e8???????? 85c0 7452 8bf0 eb2d 8b4d08 }
		$sequence_1 = { 0f84e0000000 399d2cffffff 0f84d4000000 57 56 68???????? 53 }
		$sequence_2 = { 8b01 8d55fc 52 ff7510 ff750c ff5030 6a00 }
		$sequence_3 = { 8975e0 8db1f8190110 8975e4 eb2b 8a4601 84c0 7429 }
		$sequence_4 = { e8???????? 89442410 85c0 0f849e000000 8bf8 8d4728 }
		$sequence_5 = { e8???????? c70009000000 e8???????? ebd5 8bc8 c1f905 8b0c8d409a8100 }
		$sequence_6 = { 57 ff15???????? 33c0 5f 5d c20400 55 }
		$sequence_7 = { 85c0 7414 53 ff15???????? 8b4dfc 8bc6 e8???????? }
		$sequence_8 = { 83630400 832300 8b4508 894308 8b450c }
		$sequence_9 = { 8d8534ffffff 50 8d8d7cffffff e8???????? 397df0 764d 837df408 }

	condition:
		7 of them and filesize <630784
}
