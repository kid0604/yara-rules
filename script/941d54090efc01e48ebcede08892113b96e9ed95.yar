rule case_12993_cve_2021_44077_webshell
{
	meta:
		description = "Files - file fm2.jsp"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/"
		date = "2022-06-06"
		hash1 = "8703f52c56b3164ae0becfc5a81bfda600db9aa6d0f048767a9684671ad5899b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "    Process powerShellProcess = Runtime.getRuntime().exec(command);" fullword ascii
		$s2 = "out.write((\"User:\\t\"+exec(\"whoami\")).getBytes());" fullword ascii
		$s3 = "return new String(inutStreamToOutputStream(Runtime.getRuntime().exec(cmd).getInputStream()).toByteArray(),encoding);" fullword ascii
		$s4 = "out.println(\"<pre>\"+exec(request.getParameter(\"cmd\"))+\"</pre>\");" fullword ascii
		$s5 = "out.println(\"<tr \"+((i%2!=0)?\"bgcolor=\\\"#eeeeee\\\"\":\"\")+\"><td align=\\\"left\\\">&nbsp;&nbsp;<a href=\\\"javascript:ge" ascii
		$s6 = "out.println(\"<h1>Command execution:</h1>\");" fullword ascii
		$s7 = "    String command = \"powershell.exe \" + request.getParameter(\"cmd\");" fullword ascii
		$s8 = "shell(request.getParameter(\"host\"), Integer.parseInt(request.getParameter(\"port\")));" fullword ascii
		$s9 = "out.write(exec(new String(b,0,a,\"UTF-8\").trim()).getBytes(\"UTF-8\"));" fullword ascii
		$s10 = "static void shell(String host,int port) throws UnknownHostException, IOException{" fullword ascii
		$s11 = "            powerShellProcess.getErrorStream()));" fullword ascii
		$s12 = "encoding = isNotEmpty(getSystemEncoding())?getSystemEncoding():encoding;" fullword ascii
		$s13 = "    // Executing the command" fullword ascii
		$s14 = ".getName()+\"\\\"><tt>download</tt></a></td><td align=\\\"right\\\"><tt>\"+new SimpleDateFormat(\"yyyy-MM-dd hh:mm:ss\").format(" ascii
		$s15 = "String out = exec(cmd);" fullword ascii
		$s16 = "static String exec(String cmd) {" fullword ascii
		$s17 = "            powerShellProcess.getInputStream()));" fullword ascii
		$s18 = "response.setHeader(\"Content-Disposition\", \"attachment; filename=\"+fileName);" fullword ascii
		$s19 = "out.println(\"<pre>\"+auto(request.getParameter(\"url\"),request.getParameter(\"fileName\"),request.getParameter(\"cmd\"))+\"</p" ascii
		$s20 = "    powerShellProcess.getOutputStream().close();" fullword ascii

	condition:
		uint16(0)==0x4d42 and filesize <30KB and 8 of them
}
