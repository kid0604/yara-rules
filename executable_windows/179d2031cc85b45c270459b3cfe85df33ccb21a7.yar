rule Derusbi_Backdoor_Mar17_1
{
	meta:
		description = "Detects a variant of the Derusbi backdoor"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-03-03"
		hash1 = "f87915f21dcc527981ebb6db3d332b5b341129b4af83524f59d7178e9d2a3a32"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%SystemRoot%\\System32\\wiaservc.dll" fullword wide
		$x2 = "c%WINDIR%\\PCHealth\\HelpCtr\\Binaries\\pchsvc.dll" fullword wide
		$x3 = "%Systemroot%\\Help\\perfc009.dat" fullword wide
		$x4 = "rundll32.exe \"%s\", R32 %s" fullword wide
		$x5 = "OfficeUt32.dll" fullword ascii
		$x6 = "\\\\.\\pipe\\usb%so" fullword wide
		$x7 = "\\\\.\\pipe\\usb%si" fullword wide
		$x8 = "\\tmp1.dat" wide

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 1 of them )
}
