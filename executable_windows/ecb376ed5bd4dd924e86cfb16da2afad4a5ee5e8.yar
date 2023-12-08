import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_Disable_OfficeProtectedView
{
	meta:
		description = "Detects Windows executables referencing Office ProtectedView registry keys. Observed modifying Office configurations via the registy to disable ProtectedView"
		author = "ditekSHen"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Security\\ProtectedView\\DisableInternetFilesInPV" ascii wide
		$s2 = "\\Security\\ProtectedView\\DisableAttachementsInPV" ascii wide
		$s3 = "\\Security\\ProtectedView\\DisableUnsafeLocationsInPV" ascii wide
		$h1 = "5c53656375726974795c50726f746563746564566965775c44697361626c65496e7465726e657446696c6573496e5056" nocase ascii wide
		$h2 = "5c53656375726974795c50726f746563746564566965775c44697361626c65417474616368656d656e7473496e5056" nocase ascii wide
		$h3 = "5c53656375726974795c50726f746563746564566965775c44697361626c65556e736166654c6f636174696f6e73496e5056" nocase ascii wide
		$d1 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%49%6e%74%65%72%6e%65%74%46%69%6c%65%73%49%6e%50%56" nocase ascii
		$d2 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%41%74%74%61%63%68%65%6d%65%6e%74%73%49%6e%50%56" nocase ascii
		$d3 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%55%6e%73%61%66%65%4c%6f%63%61%74%69%6f%6e%73%49%6e%50%56" nocase ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($s*) or 2 of ($h*) or 2 of ($d*))
}
