rule INDICATOR_TOOL_EXP_ApacheStrusts
{
	meta:
		author = "ditekSHen"
		description = "Detects Windows executables containing ApacheStruts exploit artifatcs"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "apache.struts2.ServletActionContext@getResponse" ascii
		$e1 = ".getWriter()" ascii
		$e2 = ".getOutputStream()" ascii
		$e3 = ".getInputStream()" ascii
		$x2 = "#_memberAccess" ascii
		$s1 = "ognl.OgnlContext" ascii
		$s2 = "ognl.ClassResolver" ascii
		$s3 = "ognl.TypeConverter" ascii
		$s4 = "ognl.MemberAccess" ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f) and ($x1 and 2 of ($e*)) or ($x2 and 1 of ($s*))
}
