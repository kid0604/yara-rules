import "pe"

rule HvS_APT37_webshell_template_query_asp
{
	meta:
		description = "Webshell named template-query.aspimg.asp used by APT37"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Moritz Oettle"
		date = "2020-12-15"
		reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
		hash = "961a66d01c86fa5982e0538215b17fb9fae2991331dfea812b8c031e2ceb0d90"
		os = "windows,linux"
		filetype = "script"

	strings:
		$g1 = "server.scripttimeout=600" fullword ascii
		$g2 = "response.buffer=true" fullword ascii
		$g3 = "response.expires=-1" fullword ascii
		$g4 = "session.timeout=600" fullword ascii
		$a1 = "redhat hacker" ascii
		$a2 = "want_pre.asp" ascii
		$a3 = "vgo=\"admin\"" ascii
		$a4 = "ywc=false" ascii
		$s1 = "public  br,ygv,gbc,ydo,yka,wzd,sod,vmd" fullword ascii

	condition:
		filesize >70KB and filesize <200KB and ((1 of ($s*)) or (2 of ($a*)) or (3 of ($g*)))
}
