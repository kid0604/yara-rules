rule win_pittytiger_rat_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.pittytiger_rat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pittytiger_rat"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7503 56 ffd3 6a50 68???????? 68???????? }
		$sequence_1 = { 85c0 0f843d010000 8d8520fcffff 56 50 8d852cffffff 50 }
		$sequence_2 = { 83c40c 8d45f4 50 6819010200 53 68???????? }
		$sequence_3 = { ff7508 e8???????? 8d8600020000 50 8d85f8fbffff 68???????? 50 }
		$sequence_4 = { 750a 68???????? e9???????? 8d85f8fdffff 56 }
		$sequence_5 = { 3bc3 a3???????? 74d1 8d459c }
		$sequence_6 = { 58 8903 eb2d 8d85fcfeffff 50 e8???????? }
		$sequence_7 = { 0f85e8000000 8d45f4 897df4 50 8d85e0feffff 50 }
		$sequence_8 = { be00010000 aa 56 8d85d0fdffff }
		$sequence_9 = { 8945f0 33ff 397df0 743c 397df8 }

	condition:
		7 of them and filesize <2162688
}
