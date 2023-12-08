rule IronTiger_ASPXSpy : HIGHVOL
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "ASPXSpy detection. It might be used by other fraudsters"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "script"

	strings:
		$str2 = "IIS Spy" wide ascii
		$str3 = "protected void DGCoW(object sender,EventArgs e)" wide ascii

	condition:
		any of ($str*)
}
