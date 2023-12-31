rule Solarmarker_Packer_2
{
	meta:
		author = "Lucas Acha (http://www.lukeacha.com)"
		description = "another version showing observed possible packer in hexdump at specific offset ranges."
		reference = "http://security5magics.blogspot.com/2020/12/tracking-jupyter-malware.html"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = "MZ"
		$off1 = { 68 6b 65 79 00 46 72 6f 6d 42 61 73 65 36 34}
		$off2 = { 70 61 63 6b 65 64 }

	condition:
		$off1 in (0x26000..0x32000) and $off2 in (0x26000..0x32000) and $mz at 0
}
