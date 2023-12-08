rule APT_Loader_Win32_DShell_2
{
	meta:
		date_created = "2020-11-27"
		date_modified = "2020-11-27"
		md5 = "590d98bb74879b52b97d8a158af912af"
		rev = 2
		author = "FireEye"
		description = "Detects APT Loader Win32 DShell variant 2"
		os = "windows"
		filetype = "executable"

	strings:
		$sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
		$ss1 = "\x00CreateThread\x00"
		$ss2 = "base64.d" fullword
		$ss3 = "core.sys.windows" fullword
		$ss4 = "C:\\Users\\config.ini" fullword
		$ss5 = "Invalid config file" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and ( uint16( uint32(0x3C)+0x18)==0x010B) and all of them
}
