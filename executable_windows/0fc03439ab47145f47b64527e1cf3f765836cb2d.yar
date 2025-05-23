rule win_lilith_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.lilith."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lilith"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4d08 898814434300 68???????? e8???????? 8be5 5d c3 }
		$sequence_1 = { 897df0 8b04bda84b4300 8955e8 8a4c0228 884dff f6c101 0f8425030000 }
		$sequence_2 = { 6bc830 8b0495a84b4300 f644082801 7421 }
		$sequence_3 = { c78558ffffff0f000000 c78554ffffff00000000 c68544ffffff00 c745fc00000000 8b3d???????? 8b1d???????? 0f1f4000 }
		$sequence_4 = { c78560ffffff00000000 6a00 50 c7855cffffff00000000 e8???????? 83c40c }
		$sequence_5 = { 83fe04 7cdc 5f 5e }
		$sequence_6 = { ffb390210000 ff15???????? 83f8ff 740f 03f0 }
		$sequence_7 = { d3c8 3305???????? 3905???????? 0f85334a0000 ff7508 e8???????? }
		$sequence_8 = { 53 8b5d10 8b0485a84b4300 56 }
		$sequence_9 = { 56 57 ff7520 8bf1 e8???????? }

	condition:
		7 of them and filesize <499712
}
