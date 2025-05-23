rule win_crypto_fortress_auto_alt_2
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.crypto_fortress."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crypto_fortress"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 341b aa 2c03 aa 2cf9 aa 2c00 }
		$sequence_1 = { 0433 aa 04fc aa 3411 }
		$sequence_2 = { e8???????? 8bd8 68???????? e8???????? 50 53 }
		$sequence_3 = { 8d3dccec4000 33c0 0450 aa }
		$sequence_4 = { 33c0 0442 aa 2ce1 }
		$sequence_5 = { 83c308 8345fc08 c78548ffffff9c000000 8d8548ffffff 50 e8???????? }
		$sequence_6 = { 8345fc04 e8???????? 8803 83c301 8345fc01 8b45fc 5b }
		$sequence_7 = { a3???????? 68???????? ff35???????? e8???????? 85c0 0f84a9030000 }
		$sequence_8 = { 3dffff0000 0f84040e0000 a3???????? e8???????? }
		$sequence_9 = { 68???????? ff35???????? e8???????? 85c0 0f842b010000 a3???????? }

	condition:
		7 of them and filesize <188416
}
