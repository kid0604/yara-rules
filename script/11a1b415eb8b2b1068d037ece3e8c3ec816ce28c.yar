import "pe"

rule sig_6898_login_webshell
{
	meta:
		description = "6898 - file login.aspx"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-11-14"
		hash1 = "98ccde0e1a5e6c7071623b8b294df53d8e750ff2fa22070b19a88faeaa3d32b0"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "<asp:TextBox id='xpath' runat='server' Width='300px'>c:\\windows\\system32\\cmd.exe</asp:TextBox>        " fullword ascii
		$s2 = "myProcessStartInfo.UseShellExecute = false            " fullword ascii
		$s3 = "\"Microsoft.Exchange.ServiceHost.exe0r" fullword ascii
		$s4 = "myProcessStartInfo.Arguments=xcmd.text            " fullword ascii
		$s5 = "myProcess.StartInfo = myProcessStartInfo            " fullword ascii
		$s6 = "myProcess.Start()            " fullword ascii
		$s7 = "myProcessStartInfo.RedirectStandardOutput = true            " fullword ascii
		$s8 = "myProcess.Close()                       " fullword ascii
		$s9 = "Dim myStreamReader As StreamReader = myProcess.StandardOutput            " fullword ascii
		$s10 = "<%@ import Namespace='system.IO' %>" fullword ascii
		$s11 = "<%@ import Namespace='System.Diagnostics' %>" fullword ascii
		$s12 = "Dim myProcess As New Process()            " fullword ascii
		$s13 = "Dim myProcessStartInfo As New ProcessStartInfo(xpath.text)            " fullword ascii
		$s14 = "example.org0" fullword ascii
		$s16 = "<script runat='server'>      " fullword ascii
		$s17 = "<asp:TextBox id='xcmd' runat='server' Width='300px' Text='/c whoami'>/c whoami</asp:TextBox>        " fullword ascii
		$s18 = "<p><asp:Button id='Button' onclick='runcmd' runat='server' Width='100px' Text='Run'></asp:Button>        " fullword ascii
		$s19 = "Sub RunCmd()            " fullword ascii

	condition:
		uint16(0)==0x8230 and filesize <6KB and 8 of them
}
