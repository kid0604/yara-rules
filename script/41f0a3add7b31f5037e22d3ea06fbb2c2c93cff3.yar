rule EXPL_PaloAlto_CVE_2024_3400_Apr24_1
{
	meta:
		description = "Detects characteristics of the exploit code used in attacks against Palo Alto GlobalProtect CVE-2024-3400"
		author = "Florian Roth"
		reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
		date = "2024-04-15"
		score = 70
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "SESSID=../../../../opt/panlogs/"
		$x2 = "SESSID=./../../../../opt/panlogs/"
		$sa1 = "SESSID=../../../../"
		$sa2 = "SESSID=./../../../../"
		$sb2 = "${IFS}"

	condition:
		1 of ($x*) or (1 of ($sa*) and $sb2)
}
