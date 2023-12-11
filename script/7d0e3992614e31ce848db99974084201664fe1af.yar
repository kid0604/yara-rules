rule CN_Honker_Webshell_ASPX_aspx2
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file aspx2.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "95db7a60f4a9245ffd04c4d9724c2745da55e9fd"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s0 = "if (password.Equals(this.txtPass.Text))" fullword ascii
		$s1 = "<head runat=\"server\">" fullword ascii
		$s2 = ":<asp:TextBox runat=\"server\" ID=\"txtPass\" Width=\"400px\"></asp:TextBox>" fullword ascii
		$s3 = "this.lblthispath.Text = Server.MapPath(Request.ServerVariables[\"PATH_INFO\"]);" fullword ascii

	condition:
		uint16(0)==0x253c and filesize <9KB and all of them
}
