rule win_sphijacker_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.sphijacker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sphijacker"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488d3d8ca9feff 488bcf e8???????? 85c0 7422 482bdf 488bd3 }
		$sequence_1 = { e8???????? 488d0daae7feff 48c1e602 0fb784b980d80100 488d9170cf0100 488d8d34030000 4c8bc6 }
		$sequence_2 = { 8a0e 884c2440 897d83 41bc01000000 4c8d1d570cffff 4181f8e9fd0000 0f857a010000 }
		$sequence_3 = { 2e0100 a0????????2e0100ae 2e0100 b52e 0100 }
		$sequence_4 = { 8a5339 8ac2 412ac6 a8df }
		$sequence_5 = { 488d15ead80100 48c7c102000080 ff15???????? 488b4d18 4c8d4520 }
		$sequence_6 = { eb88 830fff 488b6c2448 48895e2c 488b5c2440 }
		$sequence_7 = { eb10 488d3d51c90100 eb07 488d3d30c90100 4883a4248000000000 4584f6 }
		$sequence_8 = { ffc8 8bf8 410fb68c8082d80100 410fb6b48083d80100 488d1c8d00000000 8d040e 4c8bc3 }
		$sequence_9 = { 8b4814 c1e90c 4184cd 740e 488b8360040000 4883780800 7419 }

	condition:
		7 of them and filesize <808960
}