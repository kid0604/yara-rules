rule win_parasite_http_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.parasite_http."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.parasite_http"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 57 b900040000 e8???????? 8bf8 85ff 0f848a000000 56 }
		$sequence_1 = { 50 33c0 895dfc 53 53 }
		$sequence_2 = { 884df2 8d4dbc 66895dbe 668955c0 66895dc4 668945ce 66c745ec5669 }
		$sequence_3 = { e8???????? 59 85db 7407 8bcb e8???????? 8b45f0 }
		$sequence_4 = { 6a36 6689460a 58 6a34 6689460e 58 57 }
		$sequence_5 = { e8???????? b9???????? 8bd8 e8???????? 33d2 8bcb }
		$sequence_6 = { 57 8bf9 b9???????? e8???????? b9???????? 8bf0 e8???????? }
		$sequence_7 = { 57 e8???????? 03c6 50 52 }
		$sequence_8 = { 740f 8d4dfc 51 51 51 50 }
		$sequence_9 = { 53 ffd0 8bcf e8???????? 8bce e8???????? 8bcb }

	condition:
		7 of them and filesize <147456
}
