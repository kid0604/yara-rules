rule win_blackcat_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.blackcat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackcat"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ffd0 eb09 8d45f8 50 }
		$sequence_1 = { f20f10459c f20f104da4 8b4df0 8d045b 8d14f500000000 8945e4 8d1452 }
		$sequence_2 = { 84c0 0f858b010000 8d4704 31db }
		$sequence_3 = { 89c1 a3???????? ffd1 8b0d???????? 89c6 85c9 751f }
		$sequence_4 = { 8d441601 29d7 8901 8945d4 897904 0f8486000000 }
		$sequence_5 = { 0f8765ffffff 8b45e4 01d8 ff75ec ff75dc 50 e8???????? }
		$sequence_6 = { 895ddc 8b5dec 8b75e0 8b4df0 89d8 }
		$sequence_7 = { 6820010000 68???????? 6a28 eb23 81f900000200 7326 }
		$sequence_8 = { 29d9 39f9 721a 01d8 57 52 50 }
		$sequence_9 = { 56 83ec10 89ce 8b4a04 }

	condition:
		7 of them and filesize <29981696
}
