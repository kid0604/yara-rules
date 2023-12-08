rule BumbleBeeShellcode
{
	meta:
		author = "kevoreilly"
		description = "BumbleBee Loader 2023"
		cape_options = "coverage-modules=gdiplus,ntdll-protect=0"
		packed = "51bb71bd446bd7fc03cc1234fcc3f489f10db44e312c9ce619b937fad6912656"
		os = "windows"
		filetype = "executable"

	strings:
		$setpath = "setPath"
		$alloc = {B8 01 00 00 00 48 6B C0 08 48 8D 0D [2] 00 00 48 03 C8 48 8B C1 48 89 [3] 00 00 00 8B 44 [2] 05 FF 0F 00 00 25 00 F0 FF FF 8B C0 48 89}
		$hook = {48 85 C9 74 20 48 85 D2 74 1B 4C 8B C9 45 85 C0 74 13 48 2B D1 42 8A 04 0A 41 88 01 49 FF C1 41 83 E8 01 75 F0 48 8B C1 C3}
		$algo = {41 8B C1 C1 E8 0B 0F AF C2 44 3B C0 73 6A 4C 8B [3] 44 8B C8 B8 00 08 00 00 2B C2 C1 E8 05 66 03 C2 8B 94 [2] 00 00 00}

	condition:
		2 of them
}
