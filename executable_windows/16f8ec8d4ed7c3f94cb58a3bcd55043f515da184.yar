rule win_adhubllka_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.adhubllka."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.adhubllka"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 8d8dfcfcffff e8???????? 0f1085fcfcffff 8bd6 }
		$sequence_1 = { 751e a1???????? 56 ffd0 33c0 5f }
		$sequence_2 = { 50 ff5150 85c0 0f8804010000 }
		$sequence_3 = { 8b8534ffffff 03c2 33f8 c1c710 03cf 33d1 c1c20c }
		$sequence_4 = { 50 6af6 ff15???????? 8b04bd68b34100 834c0318ff 33c0 eb16 }
		$sequence_5 = { 660ffea530ffffff 660fefc8 8345f010 0f28d4 0f1108 8b45fc }
		$sequence_6 = { 8945dc 8b458c 03c7 c1c207 8bc8 334d84 c1c110 }
		$sequence_7 = { 8d041e c1c007 33458c 8d3403 c1c609 }
		$sequence_8 = { 0fbe05???????? c1e208 0bd0 c745d4bbaaffee 0fbe05???????? c1e208 0bd0 }
		$sequence_9 = { 0f28a570feffff 0f1000 8b45f0 660ffea530ffffff 660fefc8 8345f010 0f28d4 }

	condition:
		7 of them and filesize <253952
}
