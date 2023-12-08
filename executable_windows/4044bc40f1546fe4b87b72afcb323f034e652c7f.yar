import "pe"

rule OrcaRAT
{
	meta:
		Author = "PwC Cyber Threat Operations"
		Date = "2014/10/20"
		Description = "Strings inside"
		Reference = "http://pwc.blogs.com/cyber_security_updates/2014/10/orcarat-a-whale-of-a-tale.html"
		description = "Yara rule for detecting OrcaRAT malware based on specific strings inside the file"
		os = "windows"
		filetype = "executable"

	strings:
		$MZ = "MZ"
		$apptype1 = "application/x-ms-application"
		$apptype2 = "application/x-ms-xbap"
		$apptype3 = "application/vnd.ms-xpsdocument"
		$apptype4 = "application/xaml+xml"
		$apptype5 = "application/x-shockwave-flash"
		$apptype6 = "image/pjpeg"
		$err1 = "Set return time error =   %d!"
		$err2 = "Set return time   success!"
		$err3 = "Quit success!"

	condition:
		$MZ at 0 and filesize <500KB and ( all of ($apptype*) and 1 of ($err*))
}
