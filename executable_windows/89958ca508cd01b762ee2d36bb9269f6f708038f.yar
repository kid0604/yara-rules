import "pe"

rule ZxShell_Jul17
{
	meta:
		description = "Detects a ZxShell - CN threat group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://blogs.rsa.com/cat-phishing/"
		date = "2017-07-08"
		hash1 = "5d2a4cde9fa7c2fdbf39b2e2ffd23378d0c50701a3095d1e91e3cf922d7b0b16"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "zxplug -add" fullword ascii
		$x2 = "getxxx c:\\xyz.dll" fullword ascii
		$x3 = "downfile -d c:\\windows\\update.exe" fullword ascii
		$x4 = "-fromurl http://x.x.x/x.dll" fullword ascii
		$x5 = "ping 127.0.0.1 -n 7&cmd.exe /c net start %s" fullword ascii
		$x6 = "ZXNC -e cmd.exe x.x.x.x" fullword ascii
		$x7 = "(bind a cmdshell)" fullword ascii
		$x8 = "ZXFtpServer 21 20 zx" fullword ascii
		$x9 = "ZXHttpServer" fullword ascii
		$x10 = "c:\\error.htm,.exe|c:\\a.exe,.zip|c:\\b.zip\"" fullword ascii
		$x11 = "c:\\windows\\clipboardlog.txt" fullword ascii
		$x12 = "AntiSniff -a wireshark.exe" fullword ascii
		$x13 = "c:\\windows\\keylog.txt" fullword ascii

	condition:
		( filesize <10000KB and 1 of them ) or 3 of them
}
