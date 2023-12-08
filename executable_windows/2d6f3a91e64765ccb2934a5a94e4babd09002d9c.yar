rule Win7Elevatev2
{
	meta:
		description = "Detects Win7Elevate - Windows UAC bypass utility"
		author = "Florian Roth"
		reference = "http://www.pretentiousname.com/misc/W7E_Source/Win7Elevate_Inject.cpp.html"
		date = "2015-05-14"
		hash1 = "4f53ff6a04e46eda92b403faf42219a545c06c29"
		hash2 = "808d04c187a524db402c5b2be17ce799d2654bd1"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "This program attempts to bypass Windows 7's default UAC settings to run " wide
		$x2 = "Win7ElevateV2\\x64\\Release\\" ascii
		$x3 = "Run the command normally (without code injection)" wide
		$x4 = "Inject file copy && elevate command" fullword wide
		$x5 = "http://www.pretentiousname.com/misc/win7_uac_whitelist2.html" fullword wide
		$x6 = "For injection, pick any unelevated Windows process with ASLR on:" fullword wide
		$s1 = "\\cmd.exe" wide
		$s2 = "runas" wide
		$s3 = "explorer.exe" wide
		$s4 = "Couldn't load kernel32.dll" wide
		$s5 = "CRYPTBASE.dll" wide
		$s6 = "shell32.dll" wide
		$s7 = "ShellExecuteEx" ascii
		$s8 = "COMCTL32.dll" ascii
		$s9 = "ShellExecuteEx" ascii
		$s10 = "HeapAlloc" ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($x*) or all of ($s*))
}
