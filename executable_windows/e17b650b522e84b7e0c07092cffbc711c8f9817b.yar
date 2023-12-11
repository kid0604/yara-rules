import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_Enable_OfficeMacro
{
	meta:
		description = "Detects Windows executables referencing Office macro registry keys. Observed modifying Office configurations via the registy to enable macros"
		author = "ditekSHen"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Word\\Security\\VBAWarnings" ascii wide
		$s2 = "\\PowerPoint\\Security\\VBAWarnings" ascii wide
		$s3 = "\\Excel\\Security\\VBAWarnings" ascii wide
		$h1 = "5c576f72645c53656375726974795c5642415761726e696e6773" nocase ascii wide
		$h2 = "5c506f776572506f696e745c53656375726974795c5642415761726e696e6773" nocase ascii wide
		$h3 = "5c5c457863656c5c5c53656375726974795c5c5642415761726e696e6773" nocase ascii wide
		$d1 = "5c%57%6f%72%64%5c%53%65%63%75%72%69%74%79%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
		$d2 = "5c%50%6f%77%65%72%50%6f%69%6e%74%5c%53%65%63%75%72%69%74%79%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
		$d3 = "5c%5c%45%78%63%65%6c%5c%5c%53%65%63%75%72%69%74%79%5c%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($s*) or 2 of ($h*) or 2 of ($d*))
}
