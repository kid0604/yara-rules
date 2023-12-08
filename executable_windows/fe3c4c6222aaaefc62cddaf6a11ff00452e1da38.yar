rule IronTiger_HTTP_SOCKS_Proxy_soexe
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Toolset - HTTP SOCKS Proxy soexe"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "listen SOCKET error." wide ascii
		$str2 = "WSAAsyncSelect SOCKET error." wide ascii
		$str3 = "new SOCKETINFO error!" wide ascii
		$str4 = "Http/1.1 403 Forbidden" wide ascii
		$str5 = "Create SOCKET error." wide ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($str*))
}
