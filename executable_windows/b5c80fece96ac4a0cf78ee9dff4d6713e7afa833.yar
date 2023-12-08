import "pe"

rule MALWARE_Win_EXEPWSHDL
{
	meta:
		author = "ditekSHen"
		description = "Detects executable downloaders using PowerShell"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "[Ref].Assembly.GetType(" ascii wide
		$x2 = ".SetValue($null,$true)" ascii wide
		$s1 = "replace" ascii wide
		$s2 = "=@(" ascii wide
		$s3 = "[System.Text.Encoding]::" ascii wide
		$s4 = ".substring" ascii wide
		$s5 = "FromBase64String" ascii wide
		$d1 = "New-Object" ascii wide
		$d2 = "Microsoft.XMLHTTP" ascii wide
		$d3 = ".open(" ascii wide
		$d4 = ".send(" ascii wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of ($x*) and (3 of ($s*) or all of ($d*))
}
