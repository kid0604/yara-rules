import "pe"

rule wiper_unique_strings
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		company = "novetta"
		description = "Detects unique strings associated with a wiper malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "C!@I#%VJSIEOTQWPVz034vuA"
		$b = "BAISEO%$2fas9vQsfvx%$"
		$c = "1.2.7.f-hanba-win64-v1"
		$d = "md %s&copy %s\\*.* %s"
		$e = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\""
		$f = "Ge.tVol. .umeIn..for  mati.onW"

	condition:
		$a or $b or $c or $d or $e or $f
}
