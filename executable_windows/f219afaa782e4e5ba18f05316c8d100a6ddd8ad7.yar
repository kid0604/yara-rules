rule BumbleBeeLoader
{
	meta:
		author = "enzo & kevoreilly"
		description = "BumbleBee Loader"
		cape_options = "coverage-modules=gdiplus,ntdll-protect=0"
		os = "windows"
		filetype = "executable"

	strings:
		$str_set = {C7 ?? 53 65 74 50}
		$str_path = {C7 4? 04 61 74 68 00}
		$openfile = {4D 8B C? [0-70] 4C 8B C? [0-70] 41 8B D? [0-70] 4? 8B C? [0-70] FF D?}
		$createsection = {89 44 24 20 FF 93 [2] 00 00 80 BB [2] 00 00 00 8B F? 74}
		$hook = {48 85 C9 74 20 48 85 D2 74 1B 4C 8B C9 45 85 C0 74 13 48 2B D1 42 8A 04 0A 41 88 01 49 FF C1 41 83 E8 01 75 F0 48 8B C1 C3}
		$iternaljob = "IternalJob"

	condition:
		uint16(0)==0x5A4D and 2 of them
}
