rule REGEORG_Tuneller_generic
{
	meta:
		author = "Mandiant"
		date = "2021-12-20"
		date_modified = "2021-12-20"
		hash = "ba22992ce835dadcd06bff4ab7b162f9"
		reference = "https://www.mandiant.com/resources/unc3524-eye-spy-email"
		description = "Yara rule for detecting REGEORG Tuneller generic activity"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "System.Net.IPEndPoint"
		$s2 = "Response.AddHeader"
		$s3 = "Request.InputStream.Read"
		$s4 = "Request.Headers.Get"
		$s5 = "Response.Write"
		$s6 = "System.Buffer.BlockCopy"
		$s7 = "Response.BinaryWrite"
		$s8 = "SocketException soex"

	condition:
		filesize <1MB and 7 of them
}
