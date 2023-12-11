import "pe"

rule MALWARE_Osx_Genieo
{
	meta:
		author = "ditekSHen"
		description = "Detects LinqurySearch/Genieo adware"
		clamav_sig = "MALWARE.Osx.Trojan.Genieo"
		os = "macos"
		filetype = "executable"

	strings:
		$s1 = "<key>com.apple.security.get-task-allow</key>" fullword ascii
		$s2 = "U1QQFXAfCxAfRUNCH1JZXh9" ascii
		$s3 = "XVFTQ1VRQlNYH" ascii
		$s4 = "dF9HXlxfUVQQVUJCX0IQHRB" ascii
		$s5 = "Value:forHTTPHeaderField:" ascii
		$s6 = "postContent:::" fullword ascii
		$s7 = "postLog:" fullword ascii
		$s8 = "initWithBase64EncodedString:options:" fullword ascii
		$s9 = "do shell script \"%@\" with administrator privileges" fullword ascii
		$s10 = /LinqurySearch-[a-f0-9]{40,}/

	condition:
		uint16(0)==0xfacf and 6 of them
}
