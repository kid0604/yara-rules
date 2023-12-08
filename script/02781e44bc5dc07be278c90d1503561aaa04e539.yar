rule APT_WEBSHELL_HAFNIUM_Chopper_WebShell : APT Hafnium WebShell
{
	meta:
		description = "Detects Chopper WebShell Injection Variant (not only Hafnium related)"
		author = "Markus Neis,Swisscom"
		date = "2021-03-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "runat=\"server\">" nocase
		$s1 = "<script language=\"JScript\" runat=\"server\">function Page_Load(){eval(Request" nocase
		$s2 = "protected void Page_Load(object sender, EventArgs e){System.IO.StreamWriter sw = new System.IO.StreamWriter(Request.Form[\"p\"] , false, Encoding.Default);sw.Write(Request.Form[\"f\"]);"
		$s3 = "<script language=\"JScript\" runat=\"server\"> function Page_Load(){eval (Request[\"" nocase

	condition:
		filesize <10KB and $x1 and 1 of ($s*)
}
