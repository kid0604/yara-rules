rule win_halfrig_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.halfrig."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.halfrig"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 833d????????ff 752a 488d0dee900400 c705????????679f9b01 c705????????6680ec92 c705????????3f7d27f5 e8???????? }
		$sequence_1 = { 833d????????ff 7539 488d0d67740400 66c705????????fd01 c705????????6881e28d }
		$sequence_2 = { e8???????? 488d0d6c950700 e8???????? 40383d???????? 7435 660f1f440000 }
		$sequence_3 = { 75ad 0fb600 498bcf 8802 488d542420 e8???????? 488d0d58c70600 }
		$sequence_4 = { 48c1e008 488bd1 49ffc0 4833d0 4983f80f 72db 408835???????? }
		$sequence_5 = { 8802 488d542420 e8???????? 488d0d4cef0900 e8???????? 40383d???????? }
		$sequence_6 = { 488d542420 e8???????? 488d0d08830600 e8???????? 40383d???????? 7435 488bd3 }
		$sequence_7 = { 75ad 0fb600 498bcf 8802 488d542420 e8???????? 488d0df8da0500 }
		$sequence_8 = { 8802 488d542420 e8???????? 488d0df8930600 e8???????? 40383d???????? }
		$sequence_9 = { 488d0d88080800 e8???????? 40383d???????? 7435 }

	condition:
		7 of them and filesize <1369088
}