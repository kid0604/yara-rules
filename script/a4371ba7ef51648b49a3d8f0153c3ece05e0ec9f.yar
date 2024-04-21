import "pe"

rule aspx_qdajscizfzx_webshell
{
	meta:
		description = "6898 - file aspx_qdajscizfzx.aspx"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-11-14"
		hash1 = "60d22223625c86d7f3deb20f41aec40bc8e1df3ab02cf379d95554df05edf55c"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "info.FileName = \"cmd.exe\";" fullword ascii
		$s2 = "info.UseShellExecute = false;" fullword ascii
		$s3 = "info.Arguments = \"/c \" + command;" fullword ascii
		$s4 = "var dstFile = Path.Combine(dstDir, Path.GetFileName(httpPostedFile.FileName));" fullword ascii
		$s5 = "using (StreamReader streamReader = process.StandardError)" fullword ascii
		$s6 = "return httpPostedFile.FileName + \" Uploaded to: \" + dstFile;" fullword ascii
		$s7 = "httpPostedFile.InputStream.Read(buffer, 0, fileLength);" fullword ascii
		$s8 = "int fileLength = httpPostedFile.ContentLength;" fullword ascii
		$s9 = "result = result +  Environment.NewLine + \"ERROR:\" + Environment.NewLine + error;" fullword ascii
		$s10 = "ALAAAAAAAAAAA" fullword ascii
		$s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
		$s12 = "var result = delimiter +  this.RunIt(Request.Params[\"exec_code\"]) + delimiter;" fullword ascii
		$s13 = "AAAAAAAAAAAAAAAAAAAAAAAA6AAAAAAAAAAAAAAA" ascii
		$s14 = "using (StreamReader streamReader = process.StandardOutput)" fullword ascii
		$s15 = "private string RunIt(string command)" fullword ascii
		$s16 = "Process process = Process.Start(info);" fullword ascii
		$s17 = "ProcessStartInfo info = new ProcessStartInfo();" fullword ascii
		$s18 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6" ascii
		$s19 = "6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
		$s20 = "if (Request.Params[\"exec_code\"] == \"put\")" fullword ascii

	condition:
		uint16(0)==0x4221 and filesize <800KB and 8 of them
}
