rule apt_win32_dll_rat_1a53b0cp32e46g0qio7
{
	meta:
		author = "https://www.fidelissecurity.com/"
		info = "Indicators for FTA-1020"
		hash1 = "75d3d1f23628122a64a2f1b7ef33f5cf"
		hash2 = "d9821468315ccd3b9ea03161566ef18e"
		hash3 = "b9af5f5fd434a65d7aa1b55f5441c90a"
		reference = "https://github.com/fideliscyber"
		description = "Indicators for FTA-1020"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { c7 [2] 64 00 63 00 c7 [2] 69 00 62 00 c7 [2] 7a 00 7e 00 c7 [2] 2d 00 43 00 c7 [2] 59 00 2d 00 c7 [2] 3b 00 23 00 c7 [2] 3e 00 36 00 c7 [2] 2d 00 5a 00 c7 [2] 42 00 5a 00 c7 [2] 3b 00 39 00 c7 [2] 36 00 2d 00 c7 [2] 59 00 7f 00 c7 [2] 64 00 69 00 c7 [2] 68 00 63 00 c7 [2] 79 00 22 00 c7 [2] 3a 00 23 00 c7 [2] 3d 00 36 00 c7 [2] 2d 00 7f 00 c7 [2] 7b 00 37 00 c7 [2] 3c 00 3c 00 c7 [2] 23 00 3d 00 c7 [2] 24 00 2d 00 c7 [2] 61 00 64 00 c7 [2] 66 00 68 00 c7 [2] 2d 00 4a 00 c7 [2] 68 00 6e 00 c7 [2] 66 00 62 00 }
		$ = { c7 [2] 23 00 24 00 c7 [2] 24 00 33 00 c7 [2] 38 00 22 00 c7 [2] 00 00 33 00 c7 [2] 24 00 25 00 c7 [2] 3f 00 39 00 c7 [2] 38 00 0a 00 c7 [2] 04 00 23 00 c7 [2] 38 00 00 00 c7 [2] 43 00 66 00 c7 [2] 6d 00 60 00 c7 [2] 67 00 52 00 c7 [2] 6e 00 63 00 c7 [2] 7b 00 67 00 c7 [2] 70 00 00 00 c7 [2] 43 00 4d 00 c7 [2] 44 00 00 00 c7 [2] 0f 00 43 00 c7 [2] 00 00 50 00 c7 [2] 49 00 4e 00 c7 [2] 47 00 00 00 c7 [2] 11 00 12 00 c7 [2] 17 00 0e 00 c7 [2] 10 00 0e 00 c7 [2] 10 00 0e 00 c7 [2] 11 00 06 00 c7 [2] 44 00 45 00 c7 [2] 4c 00 00 00 }
		$ = { 66 [4-7] 0d 40 83 f8 44 7c ?? }
		$ = { 66 [4-7] 14 40 83 f8 14 7c ?? }
		$ = { 66 [4-7] 56 40 83 f8 2d 7c ?? }
		$ = { 66 [4-7] 20 40 83 f8 1a 7c ?? }
		$ = { 80 [2-7] 2e 40 3d 50 02 00 00 72 ?? }
		$ = "%08x%08x%08x%08x" wide ascii
		$ = "WinHttpGetIEProxyConfigForCurrentUser" wide ascii

	condition:
		( uint16(0)==0x5A4D or uint32(0)==0x4464c457f) and ( all of them )
}
