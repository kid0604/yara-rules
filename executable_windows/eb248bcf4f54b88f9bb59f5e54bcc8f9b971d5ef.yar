rule win_linseningsvr_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.linseningsvr."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.linseningsvr"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d34b558874000 832600 83c60c 4a 75f7 8b00 8b35???????? }
		$sequence_1 = { 47 3bfe 7ce7 68???????? e8???????? 8b15???????? b900010000 }
		$sequence_2 = { 83f908 7229 f3a5 ff2495982c4000 8bc7 ba03000000 }
		$sequence_3 = { e8???????? b900010000 33c0 8dbc2450040000 55 }
		$sequence_4 = { 8d3c8dc08d4000 c1e603 8b0f f644310401 7456 50 e8???????? }
		$sequence_5 = { 7c13 80fb78 7f0e 0fbec3 8a801c714000 }
		$sequence_6 = { 52 56 66895c2448 6689442456 ff15???????? 8bd8 }
		$sequence_7 = { 8944241c 33ff 8bc8 83f940 5d }
		$sequence_8 = { 8088818c400008 40 3dff000000 72f1 56 }
		$sequence_9 = { 8ac8 80c120 8888808b4000 eb1f 83f861 7213 83f87a }

	condition:
		7 of them and filesize <81360
}
