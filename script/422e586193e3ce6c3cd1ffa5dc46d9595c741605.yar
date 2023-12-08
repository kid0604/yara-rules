rule JSP_jfigueiredo_APT_webshell
{
	meta:
		description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
		author = "Florian Roth (Nextron Systems)"
		date = "12.10.2014"
		score = 60
		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/Browser.jsp"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$a1 = "String fhidden = new String(Base64.encodeBase64(path.getBytes()));" ascii
		$a2 = "<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">" ascii

	condition:
		all of them
}
