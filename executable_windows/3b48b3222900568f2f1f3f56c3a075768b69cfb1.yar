rule win_play_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.play."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.play"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 80c316 befcffffff 8ac3 02db 02c3 02c7 008528feffff }
		$sequence_1 = { 6804010000 50 e8???????? 8b95acfdffff 8d8dc8fdffff }
		$sequence_2 = { f30f7e05???????? 660fd685d8fcffff 0f1005???????? c68508fdffff00 c68566fdffff4f 0f11857cfcffff }
		$sequence_3 = { 99 8bf8 8d45c8 83c7ff 50 83d2ff 83ec08 }
		$sequence_4 = { 8b5df8 8bd3 e8???????? 0fb67dbe 8bd3 8b4de4 }
		$sequence_5 = { 000f 843402 0000 83ec04 b021 b24c }
		$sequence_6 = { e9???????? 0fb7cb 81f97e0e0000 7645 8a95cffeffff 81c182f1ffff }
		$sequence_7 = { 8945e8 0fb705???????? 668945ec a1???????? }
		$sequence_8 = { 0fb705???????? 660fd68584fdffff f30f7e05???????? 660fd68578fdffff 0f1005???????? 668985b4fdffff }
		$sequence_9 = { 8b85a8fdffff 6603fb 6640 6689bd04feffff 8985a8fdffff 41 66898588fdffff }

	condition:
		7 of them and filesize <389120
}
