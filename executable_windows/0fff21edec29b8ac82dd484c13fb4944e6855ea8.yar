rule win_cadelspy_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.cadelspy."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cadelspy"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 8d842460020000 8d4802 668b10 40 40 }
		$sequence_1 = { 83e01f c1fa05 8b1495004c0110 59 c1e006 59 }
		$sequence_2 = { 83e01f c1f905 8b0c8d004c0110 c1e006 03c1 f6400401 7524 }
		$sequence_3 = { 2bc1 d1f8 6683bc44760400005c 7411 }
		$sequence_4 = { a1???????? 33c5 89857c070000 53 8b9d88070000 56 57 }
		$sequence_5 = { 57 ff742418 57 e8???????? 83c40c ff742414 }
		$sequence_6 = { 6683bc447e0600005c 7411 68???????? 8d9c2484060000 e8???????? 8d44244c }
		$sequence_7 = { 83ffff 741d 8b54240c 56 6a64 8d442444 59 }
		$sequence_8 = { 57 6689842484060000 8d842486060000 56 50 e8???????? 83c40c }
		$sequence_9 = { 59 56 57 ff15???????? 68???????? e8???????? 68???????? }

	condition:
		7 of them and filesize <204800
}
