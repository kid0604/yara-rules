rule reDuhServers_reDuh_3
{
	meta:
		description = "Chinese Hacktool Set - file reDuh.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0744f64c24bf4c0bef54651f7c88a63e452b3b2d"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Response.Write(\"[Error]Unable to connect to reDuh.jsp main process on port \" +" ascii
		$s2 = "host = System.Net.Dns.Resolve(\"127.0.0.1\");" fullword ascii
		$s3 = "rw.WriteLine(\"[newData]\" + targetHost + \":\" + targetPort + \":\" + socketNum" ascii
		$s4 = "Response.Write(\"Error: Bad port or host or socketnumber for creating new socket" ascii

	condition:
		filesize <40KB and all of them
}
