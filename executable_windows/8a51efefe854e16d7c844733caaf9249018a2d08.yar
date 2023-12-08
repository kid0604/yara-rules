rule HKTL_RedMimicry_WinntiLoader
{
	meta:
		date = "2020-06-22"
		modified = "2023-01-10"
		author = "mirar@chaosmail.org"
		sharing = "tlp:white"
		description = "matches the Winnti 'Cooper' loader version used for the RedMimicry breach emulation"
		reference = "https://redmimicry.com"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Cooper" ascii fullword
		$s1 = "stone64.dll" ascii fullword
		$decoding_loop = { 49 63 D0 43 8D 0C 01 41 FF C0 42 32 0C 1A 0F B6 C1 C0 E9 04 C0 E0 04 02 C1 42 88 04 1A 44 3B 03 72 DE }

	condition:
		all of them
}
