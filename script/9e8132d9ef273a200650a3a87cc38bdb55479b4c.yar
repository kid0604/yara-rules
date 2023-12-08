rule Nishang_Webshell
{
	meta:
		description = "Detects a ASPX web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/samratashok/nishang"
		date = "2016-09-11"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "psi.Arguments = \"-noninteractive \" + \"-executionpolicy bypass \" + arg;" ascii
		$s2 = "output.Text += \"\nPS> \" + console.Text + \"\n\" + do_ps(console.Text);" ascii
		$s3 = "<title>Antak Webshell</title>" fullword ascii
		$s4 = "<asp:Button ID=\"executesql\" runat=\"server\" Text=\"Execute SQL Query\"" ascii

	condition:
		( uint16(0)==0x253C and filesize <100KB and 1 of ($s*))
}
