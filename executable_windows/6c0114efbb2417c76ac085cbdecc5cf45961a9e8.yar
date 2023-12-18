rule win_deathransom_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.deathransom."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deathransom"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b55d8 33c3 03c1 81c216c1a419 03d0 8bcf 0155ec }
		$sequence_1 = { 03d1 c1c007 0355a8 8bcf c1c90b 33c8 8955d8 }
		$sequence_2 = { 742d 8b45f8 ba20000000 2bd6 8bca d3e8 8bce }
		$sequence_3 = { 0f8278010000 8b5df4 8d4dd8 56 8bd3 837b0400 }
		$sequence_4 = { c3 83f802 7546 6820020000 6a08 c745fc20020000 ff15???????? }
		$sequence_5 = { 8d8d90fdffff e8???????? 8d8d90fdffff e8???????? 8d8d90fdffff e8???????? 6a50 }
		$sequence_6 = { 0b7de4 237ddc 8b55f4 0bf8 897de0 8bc6 014de0 }
		$sequence_7 = { 8b45dc 8bc8 0155e8 c1c00a }
		$sequence_8 = { 85c9 0f95c0 2bc8 33c0 c1e905 }
		$sequence_9 = { c1e810 884311 8bc1 c1e808 884312 884b13 8b4f1c }

	condition:
		7 of them and filesize <133120
}
