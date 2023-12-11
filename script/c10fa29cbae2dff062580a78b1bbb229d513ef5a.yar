rule webshell_webshells_new_JJJsp2
{
	meta:
		description = "Web shells - generated from file JJJsp2.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "5a9fec45236768069c99f0bfd566d754"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "QQ(cs, z1, z2, sb,z2.indexOf(\"-to:\")!=-1?z2.substring(z2.indexOf(\"-to:\")+4,z"
		$s8 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ"
		$s10 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData()"
		$s11 = "return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equalsIgnoreCase("

	condition:
		1 of them
}
