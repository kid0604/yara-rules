rule win_vohuk_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.vohuk."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vohuk"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 817dfc1c010000 72e5 8b0d???????? ba3196d60b 6a5d c78560feffff1c010000 c6857affffff01 }
		$sequence_1 = { 8b7df8 c7878802080001000000 8b8788020800 be40000000 898794040800 83c9ff }
		$sequence_2 = { 7507 e9???????? 32c0 5f 5e 5b }
		$sequence_3 = { 7406 880d???????? 8b4df8 8b75e4 8b45ec 8b55e8 81fe47656e75 }
		$sequence_4 = { 8b4508 53 56 8bf0 57 8b7d0c 8bd7 }
		$sequence_5 = { c5fe7f9520feffff c5fe7f9d00ffffff c5fe7f75a0 c5fe7f5de0 c5fe7f7d80 c5fe7f9d40ffffff c5fe7f95a0feffff }
		$sequence_6 = { 6a15 e8???????? 56 6a00 57 ffd0 8b35???????? }
		$sequence_7 = { 6a08 57 ffd1 8b0d???????? 8bf8 8b45f4 ba601b4656 }
		$sequence_8 = { 660f72f10c 660f72f00c 660f72f20c 0f299de0feffff 660fef5d90 660f72d714 660f72d414 }
		$sequence_9 = { c740446a017701 c7404871012601 c7404c4e017b01 c7405029014f01 c7405466017c01 c7405879017701 c7405c2f015201 }

	condition:
		7 of them and filesize <260096
}
