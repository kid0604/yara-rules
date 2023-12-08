rule win_keyboy_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.keyboy."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.keyboy"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 51 ff75d8 6a00 ff75c0 }
		$sequence_1 = { 6a00 8945f2 8d45f8 50 6a0e }
		$sequence_2 = { c705????????0caa6c89 c705????????a856701f c705????????597e743c c705????????0a9769e0 c705????????c4b85363 }
		$sequence_3 = { c3 3b0d???????? f27502 f2c3 f2e953030000 55 }
		$sequence_4 = { c705????????c4b85363 c705????????3abf261f c705????????890e9944 c705????????dbd99823 c705????????d468bcb5 c705????????2086e659 }
		$sequence_5 = { c705????????d468bcb5 c705????????2086e659 c705????????eec45abf c705????????bbee2bd1 c705????????3e20f129 c705????????42be62c1 c705????????1a78e4c7 }
		$sequence_6 = { 83c9f8 41 8a043e 0fbe4c8de0 3401 }
		$sequence_7 = { f7d9 85db 0f44c2 23c8 }
		$sequence_8 = { c1e810 884106 8bc2 c1e808 }
		$sequence_9 = { 8b4df8 8bd6 e8???????? 6a00 ffb524fdffff }
		$sequence_10 = { 85c0 741d ff15???????? 6afe 8d45f0 }
		$sequence_11 = { ffd0 e9???????? bbfeffffff eb05 }
		$sequence_12 = { c745e453686c77 c745e861706900 ffd0 8bf0 c745dc5368656c }
		$sequence_13 = { 8b75bc 8bce 8b15???????? a3???????? e8???????? }
		$sequence_14 = { e8???????? 85c0 755e 83ff20 }
		$sequence_15 = { 3bf2 7cd6 5f 5e 8be5 5d }
		$sequence_16 = { e8???????? 6a7c 8d4580 c7857cffffff736c6d00 }
		$sequence_17 = { 0fbe4c8de0 3401 0fbec0 0fafc8 80f185 880c3e 46 }
		$sequence_18 = { e8???????? 85c0 790b b883ffffff }
		$sequence_19 = { f6d8 1ac0 24dd 88474e e8???????? }
		$sequence_20 = { 24a0 3ca0 7518 b800080000 }
		$sequence_21 = { 8bf2 c745f470646174 66c745f86500 8a02 42 84c0 75f9 }
		$sequence_22 = { c705????????ba66ea37 c705????????1671e665 c705????????f3106cb3 c705????????526c1ed0 c705????????5d05606c c705????????d18e5285 c705????????7c42ca7f }
		$sequence_23 = { b901000000 eb0f 3cfe 7509 }
		$sequence_24 = { 8bd9 6a00 50 e8???????? 83c40c 8d85fcf7ffff }

	condition:
		7 of them and filesize <2170880
}
