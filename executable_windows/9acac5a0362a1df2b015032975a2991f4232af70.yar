rule apt_win32_dll_rat_hiZor_RAT : RAT
{
	meta:
		description = "Detects hiZor RAT"
		hash1 = "75d3d1f23628122a64a2f1b7ef33f5cf"
		hash2 = "d9821468315ccd3b9ea03161566ef18e"
		hash3 = "b9af5f5fd434a65d7aa1b55f5441c90a"
		ref1 = "http://www.threatgeek.com/2016/01/introducing-hi-zor-rat.html"
		ref2 = "https://github.com/Neo23x0/Loki/blob/b187ed063d73d0defc6958100ca7ad04aa77fc12/signatures/apt_hizor_rat.yar"
		reference = "https://www.fidelissecurity.com/sites/default/files/FTA_1020_Fidelis_Inocnation_FINAL.pdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { c7 [5] 40 00 62 00 c7 [5] 77 00 64 00 c7 [5] 61 00 61 00 c7 [5] 6c 00 }
		$s2 = { 66 [7] 0d 40 83 ?? ?? 7c ?? }
		$s3 = { 80 [2] 2e 40 3b ?? 72 ?? }
		$s4 = "CmdProcessExited" wide ascii
		$s5 = "rootDir" wide ascii
		$s6 = "DllRegisterServer" wide ascii
		$s7 = "GetNativeSystemInfo" wide ascii
		$s8 = "%08x%08x%08x%08x" wide ascii

	condition:
		( uint16(0)==0x5A4D or uint32(0)==0x4464c457f) and ( all of them )
}
