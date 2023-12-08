rule APT_UNC2447_PS1_WARPRISM_May21_1
{
	meta:
		description = "Detects WARPRISM PowerShell samples from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		date = "2021-05-01"
		hash1 = "3090bff3d16b0b150444c3bfb196229ba0ab0b6b826fa306803de0192beddb80"
		hash2 = "63ba6db8c81c60dd9f1a0c7c4a4c51e2e56883f063509ed7b543ad7651fd8806"
		hash3 = "b41a303a4caa71fa260dd601a796033d8bfebcaa6bd9dfd7ad956fac5229a735"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "if ($MyInvocation.MyCommand.Path -match '\\S') {" ascii fullword
		$s1 = "[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr " ascii wide
		$s2 = "[Runtime.InteropServices.Marshal]::Copy($" ascii wide
		$s3 = "[System.Diagnostics.Process]::Start((-join(" ascii wide

	condition:
		filesize <5000KB and 1 of ($x*) or 2 of them
}
