rule win_wipbot_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.wipbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wipbot"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 48 89cf 0f847f010000 48 8d4c2430 e8???????? }
		$sequence_1 = { c68424a10200000b c68424a20200007b 31c0 c68424a302000069 c68424a402000060 c68424a50200007a c68424a60200000e }
		$sequence_2 = { 48 8d0d86ffffff e8???????? 4c 8d442440 895c2420 }
		$sequence_3 = { 89c7 7504 31c0 eb72 4c 8b03 4d }
		$sequence_4 = { 48 ffc0 3211 83f22e 48 83f804 }
		$sequence_5 = { 89c7 750c e8???????? 0d00005e00 eb45 48 8b442438 }
		$sequence_6 = { 48 85c0 7437 45 31c9 }
		$sequence_7 = { 66c704430000 b801000000 eb02 31c0 48 83c428 5b }
		$sequence_8 = { ba08000000 48 89f9 41 ffd1 eb31 }
		$sequence_9 = { 81ce00009f00 e9???????? 8b44bdc8 e8???????? }

	condition:
		7 of them and filesize <253952
}
