rule CN_Honker_Webshell_ASPX_aspx_alt_1
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file aspx.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "8378619b2a7d446477946eabaa1e6744dec651c1"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii
		$s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
		$s2 = "td.Text=\"<a href=\\\"javascript:Bin_PostBack('urJG','\"+dt.Rows[j][\"ProcessID" ascii
		$s3 = "vyX.Text+=\"<a href=\\\"javascript:Bin_PostBack('Bin_Regread','\"+MVVJ(rootkey)+" ascii

	condition:
		filesize <353KB and 2 of them
}
