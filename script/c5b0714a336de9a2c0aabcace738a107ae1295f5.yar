rule WebShell_JexBoss_JSP_1
{
	meta:
		description = "Detects JexBoss JSPs"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-11-08"
		hash1 = "41e0fb374e5d30b2e2a362a2718a5bf16e73127e22f0dfc89fdb17acbe89efdf"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "equals(\"jexboss\")"
		$x2 = "%><pre><%if(request.getParameter(\"ppp\") != null &&" ascii
		$s1 = "<%@ page import=\"java.util.*,java.io.*\"%><pre><% if (request.getParameter(\""
		$s2 = "!= null && request.getHeader(\"user-agent\"" ascii
		$s3 = "String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); }}%>" fullword ascii

	condition:
		uint16(0)==0x253c and filesize <1KB and 1 of ($x*) or 2 of them
}
