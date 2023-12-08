rule webshell_webshells_new_JSP
{
	meta:
		description = "Web shells - generated from file JSP.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "495f1a0a4c82f986f4bdf51ae1898ee7"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i"
		$s5 = "bw.write(z2);bw.close();sb.append(\"1\");}else if(Z.equals(\"E\")){EE(z1);sb.app"
		$s11 = "if(Z.equals(\"A\")){String s=new File(application.getRealPath(request.getRequest"

	condition:
		1 of them
}
