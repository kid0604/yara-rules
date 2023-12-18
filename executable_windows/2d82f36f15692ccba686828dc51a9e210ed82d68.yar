rule win_pandora_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.pandora."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pandora"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 48ffcb 48899d60020000 48ffc6 c60300 4c8bc6 488d8d60020000 }
		$sequence_1 = { 458bce 41c1c90b 4433c9 44895d40 418bce 458bc3 c1c906 }
		$sequence_2 = { 4885c0 750a b880eeffff e9???????? 4d8bcf 48896c2420 4c8d442430 }
		$sequence_3 = { 488d1d43ef0200 4885c0 7404 488d5820 8bcf e8???????? 8903 }
		$sequence_4 = { 4c8d7c2430 4c2bff 4c8dab80010000 0f1f4000 0f1f840000000000 488bd5 498d4d0f }
		$sequence_5 = { 418bf8 488bea 488bf1 4d85c9 7423 498b4128 }
		$sequence_6 = { 4533b48db0050700 418bcb 44337014 c1e908 0fb6d1 8bcb }
		$sequence_7 = { 452bf8 c1ed08 452be0 8d4147 41c1ef08 41c1ec08 458d48e6 }
		$sequence_8 = { 4403d1 418bc9 4181c139a093fc 41c1c20a 4403d2 f7d1 410bca }
		$sequence_9 = { 79da 85db 0f8538020000 4c8d45cf 498bd7 488d4db7 e8???????? }

	condition:
		7 of them and filesize <1032192
}
