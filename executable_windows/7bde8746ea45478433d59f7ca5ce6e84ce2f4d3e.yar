rule win_seasalt_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.seasalt."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.seasalt"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 33c0 f2ae f7d1 83c1f3 }
		$sequence_1 = { eb02 33c0 0fbe84c660a20010 c1f804 83f807 }
		$sequence_2 = { 40 3d00010000 7cef b950000000 }
		$sequence_3 = { 8dbdd8fdffff 897de8 803f00 7433 }
		$sequence_4 = { 89442420 b911000000 33c0 8d7c2424 f3ab }
		$sequence_5 = { 0fb6fa 3bc7 7714 8b55fc 8a92c0cc0010 089001da0010 }
		$sequence_6 = { 891d???????? c705????????03000000 8935???????? 8935???????? ffd7 }
		$sequence_7 = { 896c2428 ffd6 8d4c2410 53 51 68???????? 68???????? }
		$sequence_8 = { 8dbc2419020000 c684241802000000 f3ab 66ab 6a00 }
		$sequence_9 = { 7765 ff2485f4130010 8b0d???????? 68???????? }

	condition:
		7 of them and filesize <139264
}
