rule win_metadatabin_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.metadatabin."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.metadatabin"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b45f0 894708 f20f1045e8 f20f1107 e8???????? 6a0c 6a00 }
		$sequence_1 = { 8d4aff 84c0 79dd 39f9 c745ec00000000 74bd 0fb65afe }
		$sequence_2 = { 8b542468 0fa4fe0d 21842400030000 0fa4cb0d 8b842498000000 8bbc2440020000 89b424e0020000 }
		$sequence_3 = { 8b7df0 8b5de4 83fa08 725e 8d72f8 39f1 8975e0 }
		$sequence_4 = { e8???????? b901000000 31d2 e9???????? 8b442418 89742430 895c2434 }
		$sequence_5 = { c784246605000000000000 c784246a05000000000000 c784246e05000000000000 c784247205000000000000 c784247605000000000000 c784247a05000000000000 c684247e05000000 }
		$sequence_6 = { f20f115014 f20f11481c 837e4c00 0f85f4010000 e9???????? 8b4c2450 8b542460 }
		$sequence_7 = { 8d4e2c e8???????? eb08 8d4e20 e8???????? 8b465c 85c0 }
		$sequence_8 = { 8b542438 c104240c 89442464 8b442408 c144246410 339424e4000000 338424a0000000 }
		$sequence_9 = { f00fc106 83e0c0 83f840 750e 8b4614 56 89d7 }

	condition:
		7 of them and filesize <1263616
}
