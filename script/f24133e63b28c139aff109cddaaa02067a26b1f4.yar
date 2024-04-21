rule aspx_dyukbdcxjfi
{
	meta:
		description = "9893_files - file aspx_dyukbdcxjfi.aspx"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2022/03/21/apt35-automates-initial-access-using-proxyshell/"
		date = "2022-03-21"
		hash1 = "84f77fc4281ebf94ab4897a48aa5dd7092cc0b7c78235965637eeef0908fb6c7"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "string[] commands = exec_code.Substring(\"run \".Length).Split(new[] { ';' }, StringSplitOptions.RemoveEmpty" ascii
		$s2 = "string[] commands = exec_code.Substring(\"run \".Length).Split(new[] { ';' }, StringSplitOptions.RemoveEmpty" ascii
		$s3 = "var dstFile = Path.Combine(dstDir, Path.GetFileName(httpPostedFile.FileName));" fullword ascii
		$s4 = "info.UseShellExecute = false;" fullword ascii
		$s5 = "using (StreamReader streamReader = process.StandardError)" fullword ascii
		$s6 = "return httpPostedFile.FileName + \" Uploaded to: \" + dstFile;" fullword ascii
		$s7 = "else if (exec_code.StartsWith(\"download \"))" fullword ascii
		$s8 = "string[] parts = exec_code.Substring(\"download \".Length).Split(' ');" fullword ascii
		$s9 = "Response.AppendHeader(\"Content-Disposition\", \"attachment; filename=\" + fileName);" fullword ascii
		$s10 = "result = result + Environment.NewLine + \"ERROR:\" + Environment.NewLine + error;" fullword ascii
		$s11 = "else if (exec_code == \"get\")" fullword ascii
		$s12 = "int fileLength = httpPostedFile.ContentLength;" fullword ascii

	condition:
		uint16(0)==0x4221 and filesize <800KB and 8 of them
}
