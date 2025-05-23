rule win_ransomexx_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.ransomexx."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ransomexx"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 897708 8d7b50 3bfe 7439 8b4f08 3bce }
		$sequence_1 = { 3bc1 744b 8d542420 52 }
		$sequence_2 = { 13542440 894838 8b4c247c 034c242c 89503c 8b942480000000 13542430 }
		$sequence_3 = { 57 8d45e0 e8???????? 8bf8 83c404 3bfb 0f8506020000 }
		$sequence_4 = { 83c204 c6462400 8955f0 8b5dfc 8ad0 80e27f 029018b44100 }
		$sequence_5 = { c1ee03 33fe 03df 8b7dfc 039c3db8feffff 8bb43d94feffff 03f3 }
		$sequence_6 = { 33f7 8b7d08 83c004 c1e608 8955ec 8945fc c1ef08 }
		$sequence_7 = { 89442440 89442444 89442448 e8???????? 83c40c 83bc248800000000 8d842490020000 }
		$sequence_8 = { 83c404 85c0 7539 8b55fc 8917 5f }
		$sequence_9 = { 8975dc 3338 8bda 897dec 8bfe c1ef10 81e7ff000000 }

	condition:
		7 of them and filesize <372736
}
