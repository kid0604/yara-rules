rule webshell_jsp_reverse_jsp_reverse_jspbd
{
	meta:
		description = "Web Shell - from files jsp-reverse.jsp, jsp-reverse.jsp, jspbd.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		super_rule = 1
		hash0 = "8b0e6779f25a17f0ffb3df14122ba594"
		hash1 = "ea87f0c1f0535610becadf5a98aca2fc"
		hash2 = "7d5e9732766cf5b8edca9b7ae2b6028f"
		score = 50
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "osw = new BufferedWriter(new OutputStreamWriter(os));" fullword
		$s7 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword
		$s9 = "isr = new BufferedReader(new InputStreamReader(is));" fullword

	condition:
		all of them
}
