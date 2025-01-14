rule win_blackcoffee_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.blackcoffee."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackcoffee"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 89460c eb03 897e0c 53 ff15???????? 8bc6 }
		$sequence_1 = { ff75b8 e8???????? 89460c ff15???????? 894610 8d8534ffffff }
		$sequence_2 = { 57 8bf0 ff7508 8d450c 50 8d4604 50 }
		$sequence_3 = { f3ab 8d8568ffffff 33f6 50 c745fc04010000 c78568ffffff94000000 }
		$sequence_4 = { 6a1c 6a40 aa ff15???????? 8bf0 8b4508 }
		$sequence_5 = { 8bec 81ec08020000 80a5f8feffff00 57 }
		$sequence_6 = { 59 8b35???????? 59 bf000000a0 57 }
		$sequence_7 = { 8d4628 50 ffd3 8b45f4 }
		$sequence_8 = { 8955f8 ff750c 6a00 ff15???????? 85c0 5f 741d }
		$sequence_9 = { 8365fc00 83c010 6a04 50 8d45fc 50 }

	condition:
		7 of them and filesize <118784
}
