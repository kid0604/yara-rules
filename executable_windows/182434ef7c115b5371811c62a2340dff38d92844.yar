rule Sphinx_Moth_kerberos32
{
	meta:
		description = "sphinx moth threat group file kerberos32.dll"
		author = "Kudelski Security - Nagravision SA (modified by Florian Roth)"
		reference = "www.kudelskisecurity.com"
		date = "2015-08-06"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%WINDIR%\\ativpsrz.bin" fullword ascii
		$x2 = "%WINDIR%\\ativpsrn.bin" fullword ascii
		$x3 = "kerberos32.dll" fullword wide
		$x4 = "KERBEROS64.dll" fullword ascii
		$x5 = "kerberos%d.dll" fullword ascii
		$s1 = "\\\\.\\pipe\\lsassp" fullword ascii
		$s2 = "LSASS secure pipe" fullword ascii
		$s3 = "NullSessionPipes" fullword ascii
		$s4 = "getlog" fullword ascii
		$s5 = "startlog" fullword ascii
		$s6 = "stoplog" fullword ascii
		$s7 = "Unsupported OS (%d)" fullword ascii
		$s8 = "Unsupported OS (%s)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (2 of ($x*) or all of ($s*))
}
