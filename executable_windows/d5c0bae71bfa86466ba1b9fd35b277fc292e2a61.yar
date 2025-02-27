rule win_crutch_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.crutch."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crutch"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 3944240c 0f8523060000 837e5800 0f84cb000000 8d442418 50 8d4c2408 }
		$sequence_1 = { 85c0 0f85bc000000 8b4c2458 6a00 6a00 8d86604b0000 50 }
		$sequence_2 = { c60730 4f 4e 85d2 7e0f 2bf2 }
		$sequence_3 = { 8944241c 8944242c 83f901 7507 b9???????? eb0f 83f902 }
		$sequence_4 = { 07 08cc 8b442404 56 8bb088050000 85f6 7438 }
		$sequence_5 = { 8b742424 8b9660060000 83ec10 8bcc 8911 8b9664060000 895104 }
		$sequence_6 = { 899ee8020000 e8???????? 8bf8 5f 33db 5b }
		$sequence_7 = { 0f85ab000000 837dec00 0f84a1000000 8b55f4 8b049588980710 f644180448 7452 }
		$sequence_8 = { 8db0f04b0000 8937 e8???????? 8906 c7460400000000 85db 743b }
		$sequence_9 = { 5d c3 6a6c b8???????? e8???????? 8bf9 83ec18 }

	condition:
		7 of them and filesize <1067008
}
