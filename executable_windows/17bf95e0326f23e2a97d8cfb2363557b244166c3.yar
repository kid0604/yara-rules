rule win_sanny_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.sanny."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sanny"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 85c0 7514 50 50 6a7f }
		$sequence_1 = { a1???????? dd45f4 5b dd5810 a1???????? }
		$sequence_2 = { 33f5 33fd 8bce 8bc6 c1e904 c1e01c 03c8 }
		$sequence_3 = { 68???????? 52 e8???????? 83c408 c60000 8d84244c010000 8d8c2414020000 }
		$sequence_4 = { 8bc8 c1e91d 8d0cc1 8b4204 8bd0 c1ea1d 8d2cc2 }
		$sequence_5 = { 83c002 50 8d842488000000 50 ffd3 8d8c2484000000 68???????? }
		$sequence_6 = { 8b4c2410 50 51 52 8bce c644241000 e8???????? }
		$sequence_7 = { 81c72c010000 3bf5 7cde 8d942414020000 8d842414040000 52 68???????? }
		$sequence_8 = { 83e01f 8b0c8dc0864100 8d04c1 eb05 b8???????? f6400480 }
		$sequence_9 = { 890d???????? 8b0d???????? 68???????? a3???????? 68???????? 8d420c }

	condition:
		7 of them and filesize <253952
}
