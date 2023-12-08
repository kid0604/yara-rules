rule Emdivi_Gen1
{
	meta:
		description = "Detects Emdivi Malware"
		author = "Florian Roth (Nextron Systems) @Cyber0ps"
		reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
		date = "2015-08-20"
		score = 80
		super_rule = 1
		hash1 = "17e646ca2558a65ffe7aa185ba75d5c3a573c041b897355c2721e9a8ca5fee24"
		hash2 = "3553c136b4eba70eec5d80abe44bd7c7c33ab1b65de617dbb7be5025c9cf01f1"
		hash3 = "6a331c4e654dd8ddaa2c69d260aa5f4f76f243df8b5019d62d4db5ae5c965662"
		hash4 = "90d07ea2bb80ed52b007f57d0d9a79430cd50174825c43d5746a16ee4f94ea86"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "wmic nteventlog where filename=\"SecEvent\" call cleareventlog" fullword wide
		$x2 = "del %Temp%\\*.exe %Temp%\\*.dll %Temp%\\*.bat %Temp%\\*.ps1 %Temp%\\*.cmd /f /q" fullword wide
		$x3 = "userControl-v80.exe" fullword ascii
		$s1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727.42)" fullword wide
		$s2 = "http://www.msftncsi.com" fullword wide
		$s3 = "net use | find /i \"c$\"" fullword wide
		$s4 = " /del /y & " fullword wide
		$s5 = "\\auto.cfg" wide
		$s6 = "/ncsi.txt" fullword wide
		$s7 = "Dcmd /c" fullword wide
		$s8 = "/PROXY" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <800KB and all of them
}
